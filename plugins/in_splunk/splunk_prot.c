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
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_http_common.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_connection.h>
#include <fluent-bit/http_server/flb_http_server.h>
#include <string.h>

#include "splunk.h"
#include "splunk_prot.h"

#define HTTP_CONTENT_JSON  0
#define HTTP_CONTENT_TEXT  1
#define HTTP_CONTENT_UNKNOWN 2

static void extract_xff_value(const char *value, size_t value_len,
                              const char **out_value, size_t *out_len)
{
    const char *start;
    const char *end;
    const char *comma;

    *out_value = NULL;
    *out_len = 0;

    if (value == NULL || value_len == 0) {
        return;
    }

    start = value;
    end = value + value_len;

    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }

    comma = memchr(start, ',', end - start);
    if (comma != NULL) {
        end = comma;
    }

    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }

    if (end > start) {
        *out_value = start;
        *out_len = end - start;
    }
}

static int extract_remote_address(const char *xff_value,
                                  size_t xff_value_len,
                                  struct flb_connection *connection,
                                  const char **out,
                                  size_t *out_len)
{
    const char *value = NULL;
    size_t len = 0;

    extract_xff_value(xff_value, xff_value_len, &value, &len);

    if (value == NULL && connection != NULL) {
        value = flb_connection_get_remote_address(connection);
        if (value != NULL) {
            len = strlen(value);
        }
    }

    if (value == NULL || len == 0) {
        return -1;
    }

    *out = value;
    *out_len = len;
    return 0;
}

static int append_remote_addr(struct flb_splunk *ctx,
                              struct flb_log_event_encoder *encoder,
                              const char *addr,
                              size_t addr_len)
{
    if (ctx->add_remote_addr != FLB_TRUE ||
        ctx->remote_addr_key == NULL ||
        addr == NULL || addr_len == 0) {
        return FLB_EVENT_ENCODER_SUCCESS;
    }

    return flb_log_event_encoder_append_body_values(
        encoder,
        FLB_LOG_EVENT_CSTRING_VALUE(ctx->remote_addr_key),
        FLB_LOG_EVENT_STRING_VALUE(addr, addr_len));
}

/* implements functionality to get tag from key in record */
static flb_sds_t tag_key(struct flb_splunk *ctx, msgpack_object *map)
{
    flb_sds_t tag = NULL;
    struct flb_ra_value *ra_val;

    /* If no record accessor is configured, return NULL */
    if (!ctx->ra_tag_key) {
        return NULL;
    }

    /* Use record accessor to get the value */
    ra_val = flb_ra_get_value_object(ctx->ra_tag_key, *map);
    if (!ra_val) {
        flb_plg_debug(ctx->ins, "Could not find tag_key %s in record", ctx->tag_key);
        return NULL;
    }

    /* Convert the value to string */
    if (ra_val->type == FLB_RA_STRING) {
        tag = flb_sds_create_len(ra_val->o.via.str.ptr, ra_val->o.via.str.size);
    }
    else {
        flb_plg_debug(ctx->ins, "tag_key %s value is not a string", ctx->tag_key);
    }

    /* Clean up the record accessor value */
    flb_ra_key_value_destroy(ra_val);

    return tag;
}

/*
 * Process a raw text payload for Splunk HEC requests, uses the delimited character to split records,
 * return the number of processed bytes
 */
static int process_raw_payload_pack(struct flb_splunk *ctx,
                                    struct flb_log_event_encoder *encoder,
                                    const char *ingested_auth_header,
                                    size_t ingested_auth_header_len,
                                    flb_sds_t tag,
                                    char *buf, size_t size,
                                    const char *remote_addr,
                                    size_t remote_addr_len)
{
    int ret = FLB_EVENT_ENCODER_SUCCESS;

    ret = flb_log_event_encoder_begin_record(encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_current_timestamp(encoder);
    }

    if (ctx->store_token_in_metadata == FLB_TRUE) {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("log"),
                    FLB_LOG_EVENT_STRING_VALUE(buf, size));
        }
    }

    if (ctx->store_token_in_metadata == FLB_TRUE) {
        if (ingested_auth_header != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_metadata_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("hec_token"),
                    FLB_LOG_EVENT_STRING_VALUE(ingested_auth_header,
                                               ingested_auth_header_len));
            }
        }
    }
    else {
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            if (ingested_auth_header != NULL) {
                ret = flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(ctx->store_token_key),
                    FLB_LOG_EVENT_STRING_VALUE(ingested_auth_header,
                                               ingested_auth_header_len),
                    FLB_LOG_EVENT_CSTRING_VALUE("log"),
                    FLB_LOG_EVENT_STRING_VALUE(buf, size));
            }
            else {
                ret = flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("log"),
                    FLB_LOG_EVENT_STRING_VALUE(buf, size));
            }
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = append_remote_addr(ctx, encoder,
                                 remote_addr,
                                 remote_addr_len);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(encoder);
    }

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_log_event_encoder_rollback_record(encoder);
        return -1;
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (tag) {
            ret = splunk_ingest_logs(ctx, tag, flb_sds_len(tag),
                                     encoder->output_buffer,
                                     encoder->output_length);
        }
        else {
            /* use default plugin Tag (it internal name, e.g: http.0 */
            ret = splunk_ingest_logs(ctx, NULL, 0,
                                     encoder->output_buffer,
                                     encoder->output_length);
        }
    }
    else {
        flb_plg_error(ctx->ins, "log event encoding error : %d", ret);
    }

    return ret;
}

static int process_flb_log_append(struct flb_splunk *ctx,
                                   struct flb_log_event_encoder *encoder,
                                   const char *ingested_auth_header,
                                   size_t ingested_auth_header_len,
                                   msgpack_object *record,
                                   flb_sds_t tag, flb_sds_t tag_from_record,
                                   struct flb_time tm,
                                   const char *remote_addr,
                                   size_t remote_addr_len)
{
    int ret;
    int i;
    msgpack_object_kv *kv;

    ret = flb_log_event_encoder_begin_record(encoder);

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_set_timestamp(
                encoder,
                &tm);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        /* Always build body by appending map entries so we can extend it */
        if (record->type == MSGPACK_OBJECT_MAP) {
            kv = record->via.map.ptr;
            for (i = 0; i < record->via.map.size &&
                         ret == FLB_EVENT_ENCODER_SUCCESS; i++) {
                ret = flb_log_event_encoder_append_body_values(
                        encoder,
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].key),
                        FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&kv[i].val));
            }
        }
        else {
            ret = flb_log_event_encoder_set_body_from_msgpack_object(encoder,
                                                                     record);
        }
    }

    if (ctx->store_token_in_metadata == FLB_TRUE) {
        if (ingested_auth_header != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_metadata_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE("hec_token"),
                    FLB_LOG_EVENT_STRING_VALUE(ingested_auth_header,
                                               ingested_auth_header_len));
            }
        }
    }
    else {
        if (ingested_auth_header != NULL) {
            if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                ret = flb_log_event_encoder_append_body_values(
                    encoder,
                    FLB_LOG_EVENT_CSTRING_VALUE(ctx->store_token_key),
                    FLB_LOG_EVENT_STRING_VALUE(ingested_auth_header,
                                               ingested_auth_header_len));
            }
        }
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = append_remote_addr(ctx, encoder, remote_addr, remote_addr_len);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        ret = flb_log_event_encoder_commit_record(encoder);
    }

    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
        if (tag_from_record) {
            ret = splunk_ingest_logs(ctx,
                                     tag_from_record,
                                     flb_sds_len(tag_from_record),
                                     encoder->output_buffer,
                                     encoder->output_length);
        }
        else if (tag) {
            ret = splunk_ingest_logs(ctx, tag, flb_sds_len(tag),
                                     encoder->output_buffer,
                                     encoder->output_length);
        }
        else {
            /* use default plugin Tag (it internal name, e.g: http.0 */
            ret = splunk_ingest_logs(ctx, NULL, 0,
                                     encoder->output_buffer,
                                     encoder->output_length);
        }
    }
    else {
        flb_plg_error(ctx->ins, "Error encoding record : %d", ret);
    }

    if (tag_from_record) {
        flb_sds_destroy(tag_from_record);
    }

    return ret;
}

static int process_json_payload_pack(struct flb_splunk *ctx,
                                     struct flb_log_event_encoder *encoder,
                                     const char *ingested_auth_header,
                                     size_t ingested_auth_header_len,
                                     flb_sds_t tag,
                                     char *buf, size_t size,
                                     const char *remote_addr,
                                     size_t remote_addr_len)
{
    int ret;
    size_t off = 0;
    msgpack_unpacked result;
    struct flb_time tm;
    int i = 0;
    msgpack_object *obj;
    msgpack_object record;
    flb_sds_t tag_from_record = NULL;

    flb_time_get(&tm);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            tag_from_record = NULL;
            if (ctx->tag_key) {
                tag_from_record = tag_key(ctx, &result.data);
            }

            ret = process_flb_log_append(ctx, encoder,
                                         ingested_auth_header,
                                         ingested_auth_header_len,
                                         &result.data, tag, tag_from_record, tm,
                                         remote_addr, remote_addr_len);
            if (ret != 0) {
                msgpack_unpacked_destroy(&result);
                return ret;
            }

            flb_log_event_encoder_reset(encoder);
        }
        else if (result.data.type == MSGPACK_OBJECT_ARRAY) {
            obj = &result.data;
            for (i = 0; i < obj->via.array.size; i++)
            {
                record = obj->via.array.ptr[i];

                tag_from_record = NULL;
                if (ctx->tag_key) {
                    tag_from_record = tag_key(ctx, &record);
                }

                ret = process_flb_log_append(ctx, encoder,
                                             ingested_auth_header,
                                             ingested_auth_header_len,
                                             &record, tag, tag_from_record, tm,
                                             remote_addr, remote_addr_len);
                if (ret != 0) {
                    msgpack_unpacked_destroy(&result);
                    return ret;
                }

                /* TODO : Optimize this
                 *
                 * This is wasteful, considering that we are emitting a series
                 * of records we should start and commit each one and then
                 * emit them all at once after the loop.
                 */

                flb_log_event_encoder_reset(encoder);
            }

            break;
        }
        else {
            flb_plg_error(ctx->ins, "skip record from invalid type: %i",
                         result.data.type);

            msgpack_unpacked_destroy(&result);

            return -1;
        }
    }

    msgpack_unpacked_destroy(&result);

    return 0;
}

static ssize_t parse_hec_payload_json(struct flb_splunk *ctx,
                                      struct flb_log_event_encoder *encoder,
                                      const char *ingested_auth_header,
                                      size_t ingested_auth_header_len,
                                      flb_sds_t tag,
                                      char *payload, size_t size,
                                      const char *remote_addr,
                                      size_t remote_addr_len)
{
    int ret;
    int out_size;
    char *pack;
    struct flb_pack_state pack_state;

    /* Initialize packer */
    flb_pack_state_init(&pack_state);

    /* Pack JSON as msgpack */
    ret = flb_pack_json_state(payload, size,
                              &pack, &out_size, &pack_state);
    flb_pack_state_reset(&pack_state);

    /* Handle exceptions */
    if (ret == FLB_ERR_JSON_PART) {
        flb_plg_warn(ctx->ins, "JSON data is incomplete, skipping");
        return -1;
    }
    else if (ret == FLB_ERR_JSON_INVAL) {
        flb_plg_warn(ctx->ins, "invalid JSON message, skipping");
        return -1;
    }
    else if (ret == -1) {
        return -1;
    }

    /* Process the packaged JSON and return the last byte used */
    ret = process_json_payload_pack(ctx, encoder,
                                    ingested_auth_header,
                                    ingested_auth_header_len,
                                    tag, pack, out_size,
                                    remote_addr, remote_addr_len);
    flb_free(pack);

    return ret;
}

static int handle_hec_payload(struct flb_splunk *ctx, int content_type,
                              struct flb_log_event_encoder *encoder,
                              const char *ingested_auth_header,
                              size_t ingested_auth_header_len,
                              flb_sds_t tag, char *buf, size_t size,
                              const char *remote_addr,
                              size_t remote_addr_len)
{
    int ret = -1;

    if (content_type == HTTP_CONTENT_JSON) {
        ret = parse_hec_payload_json(ctx, encoder,
                                     ingested_auth_header,
                                     ingested_auth_header_len,
                                     tag, buf, size,
                                     remote_addr, remote_addr_len);
    }
    else if (content_type == HTTP_CONTENT_TEXT) {
        ret = process_raw_payload_pack(ctx, encoder,
                                       ingested_auth_header,
                                       ingested_auth_header_len,
                                       tag, buf, size,
                                       remote_addr, remote_addr_len);
    }
    else if (content_type == HTTP_CONTENT_UNKNOWN) {
        if (buf[0] == '{') {
            ret = parse_hec_payload_json(ctx, encoder,
                                         ingested_auth_header,
                                         ingested_auth_header_len,
                                         tag, buf, size,
                                         remote_addr, remote_addr_len);
        }
        else {
            ret = process_raw_payload_pack(ctx, encoder,
                                           ingested_auth_header,
                                           ingested_auth_header_len,
                                           tag, buf, size,
                                           remote_addr, remote_addr_len);
        }
    }

    return ret;
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
    else if (http_status == 401) {
        flb_http_response_set_message(response, "Unauthorized");
    }
    else if (http_status == 503) {
        flb_http_response_set_message(response, "Service Unavailable");
    }

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int send_json_message_response_ng(struct flb_http_response *response,
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
    else if (http_status == 401) {
        flb_http_response_set_message(response, "Unauthorized");
    }

    flb_http_response_set_header(response,
                                "content-type", 0,
                                "application/json", 0);

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int validate_auth_header_ng(struct flb_splunk *ctx, struct flb_http_request *request)
{
    struct mk_list *tmp;
    struct mk_list *head;
    char *auth_header;
    struct flb_splunk_tokens *splunk_token;

    if (mk_list_size(&ctx->auth_tokens) == 0) {
        return SPLUNK_AUTH_UNAUTH;
    }

    auth_header = flb_http_request_get_header(request, "authorization");

    if (auth_header == NULL) {
        return SPLUNK_AUTH_MISSING_CRED;
    }

    if (auth_header != NULL && strlen(auth_header) > 0) {
        mk_list_foreach_safe(head, tmp, &ctx->auth_tokens) {
            splunk_token = mk_list_entry(head, struct flb_splunk_tokens, _head);
            if (strlen(auth_header) != splunk_token->length) {
                continue;
            }

            if (strncasecmp(splunk_token->header,
                        auth_header,
                        splunk_token->length) == 0) {
                return SPLUNK_AUTH_SUCCESS;
            }
        }

        return SPLUNK_AUTH_UNAUTHORIZED;
    }
    else {
        return SPLUNK_AUTH_MISSING_CRED;
    }
}

static int process_hec_payload_ng(struct flb_http_request *request,
                                  struct flb_http_response *response,
                                  flb_sds_t tag,
                                  struct flb_splunk *ctx,
                                  struct flb_log_event_encoder *encoder,
                                  const char *remote_addr,
                                  size_t remote_addr_len)
{
    int type = -1;
    int ret = 0;
    size_t size = 0;
    char *auth_header;

    type = HTTP_CONTENT_UNKNOWN;

    if (request->content_type != NULL) {
        if (strcasecmp(request->content_type, "application/json") == 0) {
            type = HTTP_CONTENT_JSON;
        }
        else if (strcasecmp(request->content_type, "text/plain") == 0) {
            type = HTTP_CONTENT_TEXT;
        }
        else {
            /* Not necessary to specify content-type for Splunk HEC. */
            flb_plg_debug(ctx->ins, "Mark as unknown type for ingested payloads");
        }
    }

    if (request->body == NULL || cfl_sds_len(request->body) <= 0) {
        send_json_message_response_ng(response, 400, "{\"text\":\"No data\",\"code\":5}");

        return -2;
    }

    ret = flb_hash_table_get(request->headers, "authorization", 13, (void **)&auth_header, &size);
    if (ret >= 0 && size > 0 && strncasecmp(auth_header, "Splunk ", 7) == 0) {
        return handle_hec_payload(ctx, type, encoder,
                                  auth_header, strlen(auth_header),
                                  tag, request->body, cfl_sds_len(request->body),
                                  remote_addr, remote_addr_len);
    }

    return handle_hec_payload(ctx, type, encoder, NULL, 0, tag,
                              request->body, cfl_sds_len(request->body),
                              remote_addr, remote_addr_len);
}

static int process_hec_raw_payload_ng(struct flb_http_request *request,
                                      struct flb_http_response *response,
                                      flb_sds_t tag,
                                      struct flb_splunk *ctx,
                                      struct flb_log_event_encoder *encoder,
                                      const char *remote_addr,
                                      size_t remote_addr_len)
{
    int ret = 0;
    size_t size = 0;
    char *auth_header;

    if (request->content_type == NULL) {
        send_response_ng(response, 400, "error: header 'Content-Type' is not set\n");

        return -1;
    }
    else if (strcasecmp(request->content_type, "text/plain") != 0) {
        /* Not necessary to specify content-type for Splunk HEC. */
        flb_plg_debug(ctx->ins, "Mark as unknown type for ingested payloads");
    }

    if (request->body == NULL || cfl_sds_len(request->body) == 0) {
        send_json_message_response_ng(response, 400, "{\"text\":\"No data\",\"code\":5}");

        return -2;
    }

    ret = flb_hash_table_get(request->headers, "authorization", 13, (void **)&auth_header, &size);
    if (ret >= 0 && size > 0 && strncasecmp(auth_header, "Splunk ", 7) == 0) {
        return process_raw_payload_pack(ctx, encoder,
                                        auth_header, strlen(auth_header),
                                        tag, request->body, cfl_sds_len(request->body),
                                        remote_addr, remote_addr_len);
    }

    /* Always handle as raw type of payloads here */
    return process_raw_payload_pack(ctx, encoder, NULL, 0, tag,
                                    request->body, cfl_sds_len(request->body),
                                    remote_addr, remote_addr_len);
}

int splunk_prot_handle_ng(struct flb_http_request *request,
                          struct flb_http_response *response)
{
    struct flb_splunk *context;
    struct flb_log_event_encoder encoder;
    int                ret = -1;
    flb_sds_t          tag;
    struct flb_http_server_session *parent_session;
    char *hval = NULL;
    size_t hlen = 0;
    const char *peer;
    const char *remote_addr = NULL;
    size_t remote_addr_len = 0;

    context = (struct flb_splunk *) response->stream->user_data;

    if (request->path[0] != '/') {
        send_response_ng(response, 400, "error: invalid request\n");
        return -1;
    }

    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {
        send_response_ng(response, 400, "error: missing host header\n");
        return -1;
    }

    if (request->method == HTTP_METHOD_GET) {
        /* Handle health monitoring of splunk hec endpoint for load balancers */
        if (strcasecmp(request->path, "/services/collector/health") == 0) {
            send_json_message_response_ng(response, 200, "{\"text\":\"Success\",\"code\":200}");
        }
        else {
            send_response_ng(response, 400, "error: invalid HTTP endpoint\n");
        }

        return 0;
    }

    /* Under services/collector endpoints are required for
     * authentication if provided splunk_token */
    ret = validate_auth_header_ng(context, request);

    if (ret < 0) {
        send_response_ng(response, 401, "error: unauthorized\n");

        if (ret == SPLUNK_AUTH_MISSING_CRED) {
            flb_plg_warn(context->ins, "missing credentials in request headers");
        }
        else if (ret == SPLUNK_AUTH_UNAUTHORIZED) {
            flb_plg_warn(context->ins, "wrong credentials in request headers");
        }

        return -1;
    }

    parent_session = (struct flb_http_server_session *) request->stream->parent;
    if (parent_session != NULL) {
        hval = flb_http_request_get_header(request, SPLUNK_XFF_HEADER);

        if (hval != NULL) {
            hlen = strlen(hval);
            extract_remote_address(hval, hlen, parent_session->connection,
                                   &remote_addr,
                                   &remote_addr_len);
        }
        if (remote_addr == NULL || remote_addr_len == 0) {
            peer = flb_connection_get_remote_address(parent_session->connection);
            if (peer != NULL) {
                remote_addr = peer;
                remote_addr_len = strlen(peer);
            }
        }
    }

    if (request->method != HTTP_METHOD_POST) {
        /* HEAD, PUT, PATCH, and DELETE methods are prohibited to use.*/
        send_response_ng(response, 400, "error: invalid HTTP method\n");

        return -1;
    }

    tag = flb_sds_create(context->ins->tag);

    if (tag == NULL) {
        return -1;
    }

    ret = flb_log_event_encoder_init(&encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);
    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_sds_destroy(tag);
        flb_plg_error(context->ins, "error initializing event encoder : %d", ret);
        return -1;
    }

    if (strcasecmp(request->path, "/services/collector/raw/1.0") == 0 ||
        strcasecmp(request->path, "/services/collector/raw") == 0) {
        ret = process_hec_raw_payload_ng(request, response, tag, context, &encoder,
                                         remote_addr, remote_addr_len);
        if (ret == -2) {
            /* Response already sent, skip further response */
            flb_log_event_encoder_destroy(&encoder);
            flb_sds_destroy(tag);
            return -1;
        }
        if (ret == FLB_INPUT_INGRESS_BUSY) {
            send_json_message_response_ng(response, 503,
                                          "{\"text\":\"Server overloaded\",\"code\":9}");
            ret = -1;
        }
        else if (ret != 0) {
            send_json_message_response_ng(response, 400, "{\"text\":\"Invalid data format\",\"code\":6}");
            ret = -1;
        }
        else {
            send_json_message_response_ng(response, 200, "{\"text\":\"Success\",\"code\":0}");
            ret = 0;
        }
    }
    else if (strcasecmp(request->path, "/services/collector/event/1.0") == 0 ||
             strcasecmp(request->path, "/services/collector/event") == 0 ||
             strcasecmp(request->path, "/services/collector") == 0) {
        ret = process_hec_payload_ng(request, response, tag, context, &encoder,
                                     remote_addr, remote_addr_len);
        if (ret == -2) {
            /* Response already sent, skip further response */
            flb_log_event_encoder_destroy(&encoder);
            flb_sds_destroy(tag);
            return -1;
        }
        if (ret == FLB_INPUT_INGRESS_BUSY) {
            send_json_message_response_ng(response, 503,
                                          "{\"text\":\"Server overloaded\",\"code\":9}");
            ret = -1;
        }
        else if (ret != 0) {
            send_json_message_response_ng(response, 400, "{\"text\":\"Invalid data format\",\"code\":6}");
            ret = -1;
        }
        else {
            send_json_message_response_ng(response, 200, "{\"text\":\"Success\",\"code\":0}");
            ret = 0;
        }
    }
    else {
        send_response_ng(response, 400, "error: invalid HTTP endpoint\n");
        ret = -1;
    }

    flb_log_event_encoder_destroy(&encoder);
    flb_sds_destroy(tag);

    return ret;
}
