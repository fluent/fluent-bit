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
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

#include <monkey/monkey.h>
#include <monkey/mk_core.h>

#include "in_elasticsearch.h"
#include "in_elasticsearch_bulk_prot.h"

#define HTTP_CONTENT_JSON   0
#define HTTP_CONTENT_NDJSON 1

/* implements functionality to get tag from key in record */
static flb_sds_t tag_key(struct flb_in_elasticsearch *ctx, msgpack_object *map)
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
        flb_plg_warn(ctx->ins, "Could not find tag_key %s in record", ctx->tag_key);
        return NULL;
    }

    /* Convert the value to string */
    if (ra_val->type == FLB_RA_STRING) {
        tag = flb_sds_create_len(ra_val->o.via.str.ptr, ra_val->o.via.str.size);
    }
    else {
        flb_plg_error(ctx->ins, "tag_key %s value is not a string or binary", ctx->tag_key);
    }

    /* Clean up the record accessor value */
    flb_ra_key_value_destroy(ra_val);
    return tag;
}

static int get_write_op(struct flb_in_elasticsearch *ctx, msgpack_object *map, flb_sds_t *out_write_op, size_t *out_key_size)
{
    char *op_str = NULL;
    size_t op_str_size = 0;
    msgpack_object_kv *kv;
    msgpack_object key;
    int check = FLB_FALSE;

    kv = map->via.map.ptr;
    key = kv[0].key;
    if (key.type == MSGPACK_OBJECT_BIN) {
        op_str  = (char *) key.via.bin.ptr;
        op_str_size = key.via.bin.size;
        check = FLB_TRUE;
    }
    if (key.type == MSGPACK_OBJECT_STR) {
        op_str  = (char *) key.via.str.ptr;
        op_str_size = key.via.str.size;
        check = FLB_TRUE;
    }

    if (check == FLB_TRUE) {
        *out_write_op = flb_sds_create_len(op_str, op_str_size);
        *out_key_size = op_str_size;
    }

    return check;
}

static int status_buffer_avail(struct flb_in_elasticsearch *ctx, flb_sds_t bulk_statuses, size_t threshold)
{
    if (flb_sds_avail(bulk_statuses) < threshold) {
        flb_plg_warn(ctx->ins, "left buffer for bulk status(es) is too small");

        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int process_ndpack(struct flb_in_elasticsearch *ctx, flb_sds_t tag, char *buf, size_t size, flb_sds_t bulk_statuses)
{
    struct flb_log_event_encoder *encoder;
    struct flb_log_event_encoder local_encoder;
    int ret;
    size_t off = 0;
    size_t map_copy_index;
    msgpack_object_kv *map_copy_entry;
    msgpack_unpacked result;
    struct flb_time tm;
    msgpack_object *obj;
    flb_sds_t tag_from_record = NULL;
    int idx = 0;
    flb_sds_t write_op = NULL;
    size_t op_str_size = 0;
    int op_ret = FLB_FALSE;
    int error_op = FLB_FALSE;
    int ingest_result = 0;
    int destroy_local_encoder = FLB_FALSE;

    if (in_elasticsearch_uses_worker_ingress_queue(ctx)) {
        ret = flb_log_event_encoder_init(&local_encoder,
                                         FLB_LOG_EVENT_FORMAT_DEFAULT);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_plg_error(ctx->ins, "event encoder initialization error : %d", ret);
            return -1;
        }

        encoder = &local_encoder;
        destroy_local_encoder = FLB_TRUE;
    }
    else {
        encoder = ctx->log_encoder;
    }

    flb_time_get(&tm);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, buf, size, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type == MSGPACK_OBJECT_MAP) {
            if (idx > 0 && idx % 2 == 0) {
                flb_sds_cat(bulk_statuses, ",", 1);
            }
            if (status_buffer_avail(ctx, bulk_statuses, 50) == FLB_FALSE) {
                break;
            }
            if (idx % 2 == 0) {
                op_ret = get_write_op(ctx, &result.data, &write_op, &op_str_size);

                if (op_ret) {
                    if (flb_sds_cmp(write_op, "index", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"index\":", 9);
                        error_op = FLB_FALSE;
                    }
                    else if (flb_sds_cmp(write_op, "create", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"create\":", 10);
                        error_op = FLB_FALSE;
                    }
                    else if (flb_sds_cmp(write_op, "update", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"update\":", 10);
                        error_op = FLB_TRUE;
                    }
                    else if (flb_sds_cmp(write_op, "delete", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"delete\":{\"status\":404,\"result\":\"not_found\"}}", 46);
                        error_op = FLB_TRUE;
                        idx += 1; /* Prepare to adjust to multiple of two
                                   * in the end of the loop.
                                   * Due to delete actions include only one line. */
                        flb_sds_destroy(write_op);

                        goto proceed;
                    }
                    else {
                        flb_sds_cat(bulk_statuses, "{\"unknown\":{\"status\":400,\"result\":\"bad_request\"}}", 49);
                        error_op = FLB_TRUE;

                        flb_sds_destroy(write_op);

                        break;
                    }
                } else {
                    flb_sds_destroy(write_op);
                    flb_plg_error(ctx->ins, "meta information line is missing");
                    error_op = FLB_TRUE;

                    break;
                }

                if (error_op == FLB_FALSE) {
                    flb_log_event_encoder_reset(encoder);

                    ret = flb_log_event_encoder_begin_record(encoder);

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_sds_destroy(write_op);
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    ret = flb_log_event_encoder_set_timestamp(
                            encoder,
                            &tm);

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_sds_destroy(write_op);
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                        ret = flb_log_event_encoder_append_body_values(
                                encoder,
                                FLB_LOG_EVENT_CSTRING_VALUE((char *) ctx->meta_key),
                                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&result.data));
                    }

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_sds_destroy(write_op);
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }
                }
            }
            else if (idx % 2 == 1) {
                if (error_op == FLB_FALSE) {
                    /* Pack body */

                    for (map_copy_index = 0 ;
                         map_copy_index < result.data.via.map.size &&
                         ret == FLB_EVENT_ENCODER_SUCCESS ;
                         map_copy_index++) {
                        map_copy_entry = &result.data.via.map.ptr[map_copy_index];

                        ret = flb_log_event_encoder_append_body_values(
                                encoder,
                                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&map_copy_entry->key),
                                FLB_LOG_EVENT_MSGPACK_OBJECT_VALUE(&map_copy_entry->val));
                    }

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    ret = flb_log_event_encoder_commit_record(encoder);

                    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                        flb_plg_error(ctx->ins, "event encoder error : %d", ret);
                        error_op = FLB_TRUE;

                        break;
                    }

                    tag_from_record = NULL;

                    if (ctx->tag_key) {
                        obj = &result.data;
                        tag_from_record = tag_key(ctx, obj);
                    }

                    if (tag_from_record) {
                        ret = in_elasticsearch_ingest_logs(ctx,
                                                           tag_from_record,
                                                           flb_sds_len(tag_from_record),
                                                           encoder->output_buffer,
                                                           encoder->output_length);

                        flb_sds_destroy(tag_from_record);
                    }
                    else if (tag) {
                        ret = in_elasticsearch_ingest_logs(ctx,
                                                           tag,
                                                           flb_sds_len(tag),
                                                           encoder->output_buffer,
                                                           encoder->output_length);
                    }
                    else {
                        /* use default plugin Tag (it internal name, e.g: http.0 */
                        ret = in_elasticsearch_ingest_logs(ctx,
                                                           NULL, 0,
                                                           encoder->output_buffer,
                                                           encoder->output_length);
                    }

                    if (ret != 0) {
                        ingest_result = ret;
                        if (ret == FLB_INPUT_INGRESS_BUSY) {
                            flb_plg_warn(ctx->ins, "deferred worker payload queue is full");
                        }
                        else {
                            flb_plg_error(ctx->ins, "could not ingest record : %d", ret);
                        }

                        error_op = FLB_TRUE;
                        flb_sds_destroy(write_op);
                        break;
                    }

                    flb_log_event_encoder_reset(encoder);
                }
                if (op_ret) {
                    if (flb_sds_cmp(write_op, "index", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"status\":201,\"result\":\"created\"}}", 34);
                    }
                    else if (flb_sds_cmp(write_op, "create", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"status\":201,\"result\":\"created\"}}", 34);
                    }
                    else if (flb_sds_cmp(write_op, "update", op_str_size) == 0) {
                        flb_sds_cat(bulk_statuses, "{\"status\":403,\"result\":\"forbidden\"}}", 36);
                    }
                    if (status_buffer_avail(ctx, bulk_statuses, 50) == FLB_FALSE) {
                        flb_sds_destroy(write_op);
                        write_op = NULL;

                        break;
                    }
                }
                flb_sds_destroy(write_op);
                write_op = NULL;
            }

        proceed:
            idx++;
        }
        else {
            flb_plg_error(ctx->ins, "skip record from invalid type: %i",
                         result.data.type);
            msgpack_unpacked_destroy(&result);
            if (destroy_local_encoder == FLB_TRUE) {
                flb_log_event_encoder_destroy(encoder);
            }
            return -1;
        }
    }

    if (idx % 2 != 0) {
        flb_plg_warn(ctx->ins, "decode payload of Bulk API is failed");
        msgpack_unpacked_destroy(&result);
        if (error_op == FLB_FALSE && write_op != NULL) {
            /* On lacking of body case in non-error case, there is no
             * releasing memory code paths. We should proceed to do
             * it here. */
            flb_sds_destroy(write_op);
        }

        if (destroy_local_encoder == FLB_TRUE) {
            flb_log_event_encoder_destroy(encoder);
        }

        return -1;
    }

    msgpack_unpacked_destroy(&result);

    if (ingest_result != 0) {
        if (destroy_local_encoder == FLB_TRUE) {
            flb_log_event_encoder_destroy(encoder);
        }

        return ingest_result;
    }

    if (destroy_local_encoder == FLB_TRUE) {
        flb_log_event_encoder_destroy(encoder);
    }

    return 0;
}

static ssize_t parse_payload_ndjson(struct flb_in_elasticsearch *ctx, flb_sds_t tag,
                                    char *payload, size_t size, flb_sds_t bulk_statuses)
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
    ret = process_ndpack(ctx, tag, pack, out_size, bulk_statuses);
    flb_free(pack);

    return ret;
}

/* New gen HTTP server */
static int send_response_ng(struct flb_http_response *response,
                            int http_status,
                            char *content_type,
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

    if (content_type != NULL) {
        flb_http_response_set_header(response,
                                     "content-type", 0,
                                     content_type, 0);
    }

    if (message != NULL) {
        flb_http_response_set_body(response,
                                   (unsigned char *) message,
                                   strlen(message));
    }

    flb_http_response_commit(response);

    return 0;
}

static int send_json_response_ng(struct flb_http_response *response,
                                 int http_status,
                                 char *message)
{
    return send_response_ng(response, http_status, "application/json", message);
}

static int send_version_message_response_ng(struct flb_http_response *response,
                                            struct flb_in_elasticsearch *ctx,
                                            int http_status)
{
    flb_sds_t message;

    if (http_status != 200) {
        return 0;
    }

    message = flb_sds_create_size(384);

    if (message == NULL) {
        return -1;
    }

    flb_sds_printf(&message,
                   ES_VERSION_RESPONSE_TEMPLATE,
                   ctx->es_version);

    send_json_response_ng(response, http_status, message);

    cfl_sds_destroy(message);

    return 0;
}

static int send_dummy_sniffer_response_ng(struct flb_http_response *response,
                                          struct flb_in_elasticsearch *ctx,
                                          int http_status)
{
    flb_sds_t hostname;
    flb_sds_t resp;

    if (http_status != 200) {
        return 0;
    }

    if (ctx->hostname != NULL) {
        hostname = ctx->hostname;
    }
    else {
        hostname = "localhost";
    }

    resp = flb_sds_create_size(384);
    if (!resp) {
        return -1;
    }

    flb_sds_printf(&resp,
                   ES_NODES_TEMPLATE,
                   ctx->cluster_name, ctx->node_name,
                   hostname, ctx->tcp_port, ctx->ins->http_server_config->buffer_max_size);

    send_json_response_ng(response, http_status, resp);

    flb_sds_destroy(resp);

    return 0;
}

static int process_payload_ng(struct flb_http_request *request,
                              struct flb_http_response *response,
                              struct flb_in_elasticsearch *context,
                              flb_sds_t tag,
                              flb_sds_t bulk_statuses)
{
    if (request->content_type == NULL) {
        send_response_ng(response, 400, NULL, "error: header 'Content-Type' is not set\n");

        return -1;
    }

    if (strncasecmp(request->content_type, "application/x-ndjson", 20) != 0 &&
        strncasecmp(request->content_type, "application/json", 16) != 0) {
        send_response_ng(response, 400, NULL, "error: invalid 'Content-Type'\n");

        return -1;
    }

    if (request->body == NULL || cfl_sds_len(request->body) == 0) {
        send_response_ng(response, 400, NULL, "error: no payload found\n");
        return -1;
    }

    return parse_payload_ndjson(context, tag, request->body,
                                cfl_sds_len(request->body), bulk_statuses);
}

int in_elasticsearch_bulk_prot_handle_ng(struct flb_http_request *request,
                                         struct flb_http_response *response)
{
    flb_sds_t                    bulk_statuses;
    flb_sds_t                    bulk_response;
    const char                  *error_str;
    struct flb_in_elasticsearch *context;
    int                          result;
    flb_sds_t                    tag;
    size_t                       len;

    bulk_statuses = NULL;
    bulk_response = NULL;

    context = (struct flb_in_elasticsearch *) response->stream->user_data;

    if (request->path[0] != '/') {
        send_response_ng(response, 400, NULL, "error: invalid request\n");
        return -1;
    }

    /* HTTP/1.1 needs Host header */
    if (request->protocol_version == HTTP_PROTOCOL_VERSION_11 &&
        request->host == NULL) {

        return -1;
    }

    if (request->method == HTTP_METHOD_HEAD) {
        send_response_ng(response, 200, NULL, NULL);

        return -1;
    }
    else if (request->method == HTTP_METHOD_PUT) {
        send_json_response_ng(response, 200, "{}");

        return -1;
    }
    else if (request->method == HTTP_METHOD_GET) {
        if (strncmp(request->path, "/_nodes/http", 12) == 0) {
            send_dummy_sniffer_response_ng(response, context, 200);
        }
        else if (strcmp(request->path, "/") == 0) {
            send_version_message_response_ng(response, context, 200);
        }
        else {
            send_json_response_ng(response, 200, "{}");
        }

        return 0;
    }
    else if (request->method == HTTP_METHOD_POST) {
        if (strcmp(request->path, "/_bulk") == 0) {
            bulk_statuses = flb_sds_create_size(context->ins->http_server_config->buffer_max_size);

            if (bulk_statuses == NULL) {
                return -1;
            }

            bulk_response = flb_sds_create_size(context->ins->http_server_config->buffer_max_size);

            if (bulk_response == NULL) {
                flb_sds_destroy(bulk_statuses);
                return -1;
            }

            tag = flb_sds_create(context->ins->tag);

            if (tag == NULL) {
                flb_sds_destroy(bulk_statuses);
                flb_sds_destroy(bulk_response);
                return -1;
            }

            result = process_payload_ng(request, response, context, tag, bulk_statuses);

            flb_sds_destroy(tag);

            if (result == FLB_INPUT_INGRESS_BUSY) {
                send_response_ng(response, 503, NULL,
                                 "error: deferred ingress queue is full\n");
                flb_sds_destroy(bulk_statuses);
                flb_sds_destroy(bulk_response);
                return -1;
            }
            else if (result != 0) {
                flb_sds_destroy(bulk_statuses);
                flb_sds_destroy(bulk_response);
                return -1;
            }

            len = flb_sds_len(bulk_statuses);

            if (flb_sds_alloc(bulk_response) < len + 27) {
                bulk_response = flb_sds_increase(bulk_response, len + 27 - flb_sds_alloc(bulk_response));
            }

            error_str = strstr(bulk_statuses, "\"status\":40");

            if (error_str){
                flb_sds_cat(bulk_response, "{\"errors\":true,\"items\":[", 24);
            }
            else {
                flb_sds_cat(bulk_response, "{\"errors\":false,\"items\":[", 25);
            }

            flb_sds_cat(bulk_response, bulk_statuses, flb_sds_len(bulk_statuses));
            flb_sds_cat(bulk_response, "]}", 2);

            send_json_response_ng(response, 200, bulk_response);

            flb_sds_destroy(bulk_statuses);
            flb_sds_destroy(bulk_response);

        } else {
            send_response_ng(response, 400, NULL, "error: invalid HTTP endpoint\n");

            return -1;
        }
    }
    else {
        send_response_ng(response, 400, NULL, "error: invalid HTTP method\n");

        return -1;
    }

    return 0;
}
