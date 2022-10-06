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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <cmetrics/cmt_encode_opentelemetry.h>

#include <fluent-otel-proto/fluent-otel.h>
#include "opentelemetry.h"
#include "opentelemetry_conf.h"

static int http_post(struct opentelemetry_context *ctx,
                     const void *body, size_t body_len,
                     const char *tag, int tag_len,
                     const char *uri)
{
    int ret;
    int out_ret = FLB_OK;
    size_t b_sent;
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_http_client *c;
    struct mk_list *head;
    struct flb_config_map_val *mv;
    struct flb_slist_entry *key = NULL;
    struct flb_slist_entry *val = NULL;

    /* Get upstream context and connection */
    u = ctx->u;
    u_conn = flb_upstream_conn_get(u);
    if (!u_conn) {
        flb_plg_error(ctx->ins, "no upstream connections available to %s:%i",
                      u->tcp_host, u->tcp_port);
        return FLB_RETRY;
    }

    /* Create HTTP client context */
    c = flb_http_client(u_conn, FLB_HTTP_POST, uri,
                        body, body_len,
                        ctx->host, ctx->port,
                        ctx->proxy, 0);


    if (c->proxy.host) {
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
    if (ctx->http_user && ctx->http_passwd) {
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
                c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                              ctx->host, ctx->port,
                              c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_error(ctx->ins, "%s:%i, HTTP status=%i",
                              ctx->host, ctx->port, c->resp.status);
            }
            out_ret = FLB_RETRY;
        }
        else {
            if (ctx->log_response_payload &&
                c->resp.payload && c->resp.payload_size > 0) {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i\n%s",
                             ctx->host, ctx->port,
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_info(ctx->ins, "%s:%i, HTTP status=%i",
                             ctx->host, ctx->port,
                             c->resp.status);
            }
        }
    }
    else {
        flb_plg_error(ctx->ins, "could not flush records to %s:%i (http_do=%i)",
                      ctx->host, ctx->port, ret);
        out_ret = FLB_RETRY;
    }

    /* Destroy HTTP client context */
    flb_http_client_destroy(c);

    /* Release the TCP connection */
    flb_upstream_conn_release(u_conn);

    return out_ret;
}

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

static void clear_array(Opentelemetry__Proto__Logs__V1__LogRecord **logs,
                        size_t log_count)
{
    size_t index;

    if (logs == NULL){
        return;
    }

    for (index = 0 ; index < log_count ; index++) {
        if (logs[index]->body->string_value) {
            flb_free(logs[index]->body->string_value);
            logs[index]->body->string_value = NULL;
        }
    }
}

static int flush_to_otel(struct opentelemetry_context *ctx,
                         struct flb_event_chunk *event_chunk,
                         Opentelemetry__Proto__Logs__V1__LogRecord **logs,
                         size_t log_count)
{
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest export_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs scope_log;
    Opentelemetry__Proto__Logs__V1__ResourceLogs resource_log;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_logs[1];
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_logs[1];
    void *body;
    unsigned len;
    int res;

    opentelemetry__proto__collector__logs__v1__export_logs_service_request__init(&export_logs);
    opentelemetry__proto__logs__v1__resource_logs__init(&resource_log);
    opentelemetry__proto__logs__v1__scope_logs__init(&scope_log);

    scope_log.log_records = logs;
    scope_log.n_log_records = log_count;
    scope_logs[0] = &scope_log;

    resource_log.scope_logs =  scope_logs;
    resource_log.n_scope_logs = 1;
    resource_logs[0] = &resource_log;

    export_logs.resource_logs = resource_logs;
    export_logs.n_resource_logs = 1;

    len = opentelemetry__proto__collector__logs__v1__export_logs_service_request__get_packed_size(&export_logs);
    body = flb_calloc(len, sizeof(char));
    if (!body) {
        flb_errno();
        return FLB_ERROR;
    }

    opentelemetry__proto__collector__logs__v1__export_logs_service_request__pack(&export_logs, body);

    // send post request to opentelemetry with content type application/x-protobuf
    res = http_post(ctx, body, len,
                    event_chunk->tag,
                    flb_sds_len(event_chunk->tag),
                    ctx->logs_uri);

    flb_free(body);

    return res;
}

static int process_logs(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *ins, void *out_context,
                        struct flb_config *config)
{
    Opentelemetry__Proto__Logs__V1__LogRecord *log_record_list[FLB_LOG_RECORD_BATCH_SIZE];
    Opentelemetry__Proto__Logs__V1__LogRecord log_records[FLB_LOG_RECORD_BATCH_SIZE];
    Opentelemetry__Proto__Common__V1__AnyValue log_bodies[FLB_LOG_RECORD_BATCH_SIZE];
    size_t log_record_count;
    size_t index;
    msgpack_unpacked result;
    msgpack_object *obj;
    size_t off = 0;
    struct flb_time tm;
    char *json;
    int res = FLB_OK;
    struct opentelemetry_context *ctx;

    for(index = 0 ; index < FLB_LOG_RECORD_BATCH_SIZE ; index++) {
        opentelemetry__proto__logs__v1__log_record__init(&log_records[index]);
        opentelemetry__proto__common__v1__any_value__init(&log_bodies[index]);

        log_bodies[index].value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;

        log_records[index].body = &log_bodies[index];

        log_record_list[index] = &log_records[index];
    }

    ctx = out_context;
    log_record_count = 0;

    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result,
                                event_chunk->data,
                                event_chunk->size, &off) == MSGPACK_UNPACK_SUCCESS) {

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        if (result.data.via.array.size != 2){
            continue;
        }

        /* unpack the array of [timestamp, map] */
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        json = flb_msgpack_to_json_str(1024, obj);

        if (json == NULL) {
            clear_array(log_record_list, log_record_count);
            flb_plg_error(ctx->ins, "failed to convert msgpack to json");
            return FLB_ERROR;
        }

        log_bodies[log_record_count].string_value = json;
        log_records[log_record_count].time_unix_nano = flb_time_to_nanosec(&tm);

        log_record_count++;

        if (log_record_count >= FLB_LOG_RECORD_BATCH_SIZE) {
            res = flush_to_otel(ctx,
                                event_chunk,
                                log_record_list,
                                log_record_count);

            clear_array(log_record_list, log_record_count);

            log_record_count = 0;

            if (res != FLB_OK) {
                return res;
            }
        }
    }

    if (log_record_count >= 0) {
        res = flush_to_otel(ctx,
                            event_chunk,
                            log_record_list,
                            log_record_count);

        clear_array(log_record_list, log_record_count);

        log_record_count = 0;
    }

    msgpack_unpacked_destroy(&result);

    return res;
}

static int process_metrics(struct flb_event_chunk *event_chunk,
                    struct flb_output_flush *out_flush,
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
            result = http_post(ctx, buf, flb_sds_len(buf),
                               event_chunk->tag,
                               flb_sds_len(event_chunk->tag),
                               ctx->metrics_uri);

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
        return FLB_ERROR;
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

    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_opentelemetry_flush(struct flb_event_chunk *event_chunk,
                                   struct flb_output_flush *out_flush,
                                   struct flb_input_instance *ins, void *out_context,
                                   struct flb_config *config)
{
    int result;
    if (ins->event_type == FLB_OUTPUT_METRICS || ins->event_type == FLB_INPUT_METRICS){
        result = process_metrics(event_chunk, out_flush, ins, out_context, config);
    }
    else if (ins->event_type == FLB_INPUT_LOGS || ins->event_type == FLB_OUTPUT_LOGS){
        result = process_logs(event_chunk, out_flush, ins, out_context, config);
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
     FLB_CONFIG_MAP_STR, "logs_uri", "/v1/logs",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_uri),
     "Specify an optional HTTP URI for the target OTel endpoint."
    },
    {
     FLB_CONFIG_MAP_BOOL, "log_response_payload", "true",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, log_response_payload),
     "Specify if the response paylod should be logged or not"
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
    .event_type  = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
