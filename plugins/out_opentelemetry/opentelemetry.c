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
#include <cmetrics/cmt_encode_opentelemetry.h>

#include <ctraces/ctraces.h>
#include <ctraces/ctr_decode_msgpack.h>

extern cfl_sds_t cmt_encode_opentelemetry_create(struct cmt *cmt);
extern void cmt_encode_opentelemetry_destroy(cfl_sds_t text);

#include "opentelemetry.h"
#include "opentelemetry_conf.h"


static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_object_to_otlp_any_value(struct msgpack_object *o);

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value);
static inline void otlp_kvarray_destroy(Opentelemetry__Proto__Common__V1__KeyValue **kvarray, size_t entry_count);
static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair);
static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist);
static inline void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array);

static inline void otlp_kvarray_destroy(Opentelemetry__Proto__Common__V1__KeyValue **kvarray, size_t entry_count)
{
    size_t index;

    if (kvarray != NULL) {
        for (index = 0 ; index < entry_count ; index++) {
            if (kvarray[index] != NULL) {
                otlp_kvpair_destroy(kvarray[index]);
                kvarray[index] = NULL;
            }
        }

        flb_free(kvarray);
    }
}

static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair)
{
    if (kvpair == NULL) {
        return;
    }

    if (kvpair->key != NULL) {
        flb_free(kvpair->key);
    }

    if (kvpair->value != NULL) {
        otlp_any_value_destroy(kvpair->value);
    }

    flb_free(kvpair);
}

static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist)
{
    size_t index;

    if (kvlist != NULL) {
        if (kvlist->values != NULL) {
            for (index = 0 ; index < kvlist->n_values ; index++) {
                otlp_kvpair_destroy(kvlist->values[index]);
            }

            flb_free(kvlist->values);
        }

        flb_free(kvlist);
    }
}

static inline void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array)
{
    size_t index;

    if (array != NULL) {
        if (array->values != NULL) {
            for (index = 0 ; index < array->n_values ; index++) {
                otlp_any_value_destroy(array->values[index]);
            }

            flb_free(array->values);
        }

        flb_free(array);
    }
}

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value)
{
    if (value != NULL) {
        if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
            if (value->string_value != NULL) {
                flb_free(value->string_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE) {
            if (value->array_value != NULL) {
                otlp_array_destroy(value->array_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
            if (value->kvlist_value != NULL) {
                otlp_kvlist_destroy(value->kvlist_value);
            }
        }
        else if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE) {
            if (value->bytes_value.data != NULL) {
                flb_free(value->bytes_value.data);
            }
        }

        value->string_value = NULL;

        flb_free(value);
    }
}

static int http_post(struct opentelemetry_context *ctx,
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
        flb_http_set_content_encoding_gzip(c);
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

            out_ret = FLB_RETRY;
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
        if (logs[index]->body != NULL) {
            otlp_any_value_destroy(logs[index]->body);

            logs[index]->body = NULL;
        }

        if (logs[index]->attributes != NULL) {
            otlp_kvarray_destroy(logs[index]->attributes,
                                 logs[index]->n_attributes);

            logs[index]->attributes = NULL;
        }
        if (logs[index]->severity_text != NULL) {
            flb_free(logs[index]->severity_text);
        }
        if (logs[index]->span_id.data != NULL) {
            flb_free(logs[index]->span_id.data);
        }
        if (logs[index]->trace_id.data != NULL) {
            flb_free(logs[index]->trace_id.data);
        }
    }
}

static Opentelemetry__Proto__Common__V1__ArrayValue *otlp_array_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__ArrayValue *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__ArrayValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__array_value__init(value);

        if (entry_count > 0) {
            value->values = \
                flb_calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__AnyValue *));

            if (value->values == NULL) {
                flb_free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValue *otlp_kvpair_value_initialize()
{
    Opentelemetry__Proto__Common__V1__KeyValue *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value__init(value);
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValueList *otlp_kvlist_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValueList *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValueList));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value_list__init(value);

        if (entry_count > 0) {
            value->values = \
                flb_calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

            if (value->values == NULL) {
                flb_free(value);

                value = NULL;
            }
            else {
                value->n_values = entry_count;
            }
        }
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__AnyValue *otlp_any_value_initialize(int data_type, size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    value = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__AnyValue));

    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__any_value__init(value);

    if (data_type == MSGPACK_OBJECT_STR) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_NIL) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE__NOT_SET;
    }
    else if (data_type == MSGPACK_OBJECT_BOOLEAN) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_POSITIVE_INTEGER || data_type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_FLOAT32 || data_type == MSGPACK_OBJECT_FLOAT64) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    }
    else if (data_type == MSGPACK_OBJECT_ARRAY) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;
        value->array_value = otlp_array_value_initialize(entry_count);

        if (value->array_value == NULL) {
            flb_free(value);

            value = NULL;
        }
    }
    else if (data_type == MSGPACK_OBJECT_MAP) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;

        value->kvlist_value = otlp_kvlist_value_initialize(entry_count);

        if (value->kvlist_value == NULL) {
            flb_free(value);

            value = NULL;
        }
    }
    else if (data_type == MSGPACK_OBJECT_BIN) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    }
    else {
        flb_free(value);

        value = NULL;
    }

    return value;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_boolean_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_BOOLEAN, 0);

    if (result != NULL) {
        result->bool_value = o->via.boolean;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_integer_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(o->type, 0);

    if (result != NULL) {
        if (o->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            result->int_value = (int64_t) o->via.u64;
        }
        else {
            result->int_value = o->via.i64;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_float_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(o->type, 0);

    if (result != NULL) {
        result->double_value = o->via.f64;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_string_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_STR, 0);

    if (result != NULL) {
        result->string_value = flb_strndup(o->via.str.ptr, o->via.str.size);

        if (result->string_value == NULL) {
            otlp_any_value_destroy(result);

            result = NULL;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_nil_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_NIL, 0);

    if (result != NULL) {
        result->string_value = NULL;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_bin_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(MSGPACK_OBJECT_BIN, 0);

    if (result != NULL) {
        result->bytes_value.len = o->via.bin.size;
        result->bytes_value.data = flb_malloc(o->via.bin.size);

        if (result->bytes_value.data == NULL) {
            otlp_any_value_destroy(result);

            result = NULL;
        }

        memcpy(result->bytes_value.data, o->via.bin.ptr, o->via.bin.size);
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_array_to_otlp_any_value(struct msgpack_object *o)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__AnyValue *entry_value;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    size_t                                      index;
    msgpack_object                             *p;

    entry_count = o->via.array.size;
    result = otlp_any_value_initialize(MSGPACK_OBJECT_ARRAY, entry_count);

    p = o->via.array.ptr;

    if (result != NULL) {
        index = 0;

        for (index = 0 ; index < entry_count ; index++) {
            entry_value = msgpack_object_to_otlp_any_value(&p[index]);

            if (entry_value == NULL) {
                otlp_any_value_destroy(result);

                result = NULL;

                break;
            }

            result->array_value->values[index] = entry_value;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__KeyValue *msgpack_kv_to_otlp_any_value(struct msgpack_object_kv *input_pair)
{
    Opentelemetry__Proto__Common__V1__KeyValue *kv;

    kv = otlp_kvpair_value_initialize();
    if (kv == NULL) {
        flb_errno();

        return NULL;
    }

    kv->key = flb_strndup(input_pair->key.via.str.ptr, input_pair->key.via.str.size);
    if (kv->key == NULL) {
        flb_errno();
        flb_free(kv);

        return NULL;
    }

    kv->value = msgpack_object_to_otlp_any_value(&input_pair->val);
    if (kv->value == NULL) {
        flb_free(kv->key);
        flb_free(kv);

        return NULL;
    }

    return kv;
}

static inline Opentelemetry__Proto__Common__V1__KeyValue **msgpack_map_to_otlp_kvarray(struct msgpack_object *o, size_t *entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValue **result;
    size_t                                       index;
    msgpack_object_kv                           *kv;

    *entry_count = o->via.map.size;
    result = flb_calloc(*entry_count, sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
    if (result != NULL) {
        for (index = 0; index < *entry_count; index++) {
            kv = &o->via.map.ptr[index];
            result[index] = msgpack_kv_to_otlp_any_value(kv);
        }
    }
    else {
        *entry_count = 0;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_map_to_otlp_any_value(struct msgpack_object *o)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    Opentelemetry__Proto__Common__V1__KeyValue *keyvalue;
    size_t                                      index;
    msgpack_object_kv                          *kv;

    entry_count = o->via.map.size;
    result = otlp_any_value_initialize(MSGPACK_OBJECT_MAP, entry_count);

    if (result != NULL) {

        for (index = 0; index < entry_count; index++) {
            kv = &o->via.map.ptr[index];
            keyvalue = msgpack_kv_to_otlp_any_value(kv);
            result->kvlist_value->values[index] = keyvalue;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *msgpack_object_to_otlp_any_value(struct msgpack_object *o)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = NULL;

    switch (o->type) {
        case MSGPACK_OBJECT_NIL:
            result = msgpack_nil_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_BOOLEAN:
            result = msgpack_boolean_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_POSITIVE_INTEGER:
        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            result = msgpack_integer_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_FLOAT32:
        case MSGPACK_OBJECT_FLOAT64:
            result = msgpack_float_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_STR:
            result = msgpack_string_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_MAP:
            result = msgpack_map_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_BIN:
            result = msgpack_bin_to_otlp_any_value(o);
            break;

        case MSGPACK_OBJECT_ARRAY:
            result = msgpack_array_to_otlp_any_value(o);
            break;

        default:
            break;
    }

    /* This function will fail if it receives an object with
     * type MSGPACK_OBJECT_EXT
     */

    return result;
}

static inline int log_record_set_body(struct opentelemetry_context *ctx,
                                     Opentelemetry__Proto__Logs__V1__LogRecord  *log_records, struct flb_log_event *event,
                                     struct flb_record_accessor **out_ra_match)
{
    int ret;
    struct mk_list *head;
    struct opentelemetry_body_key *bk;
    msgpack_object *s_key = NULL;
    msgpack_object *o_key = NULL;
    msgpack_object *o_val = NULL;
    Opentelemetry__Proto__Common__V1__AnyValue *log_object = NULL;

    *out_ra_match = NULL;
    mk_list_foreach(head, &ctx->log_body_key_list) {
        bk = mk_list_entry(head, struct opentelemetry_body_key, _head);

        ret = flb_ra_get_kv_pair(bk->ra, *event->body, &s_key, &o_key, &o_val);
        if (ret == 0) {
            log_object = msgpack_object_to_otlp_any_value(o_val);

            /* Link the record accessor pattern that matched */
            *out_ra_match = bk->ra;
            break;
        }

        log_object = NULL;
    }

    /* At this point the record accessor patterns found nothing, so we just package the whole record */
    if (!log_object) {
        log_object = msgpack_object_to_otlp_any_value(event->body);
    }

    if (!log_object) {
        flb_plg_error(ctx->ins, "log event conversion failure");
        return -1;
    }

    /* try to find the following keys: message or log, if found */
    log_records->body = log_object;
    return 0;
}

static int log_record_set_attributes(struct opentelemetry_context *ctx,
                                     Opentelemetry__Proto__Logs__V1__LogRecord *log_record, struct flb_log_event *event,
                                     struct flb_record_accessor *ra_match)
{
    int i;
    int ret;
    int attr_count = 0;
    int unpacked = FLB_FALSE;
    size_t array_size;
    void *out_buf;
    size_t offset = 0;
    size_t out_size;
    msgpack_object_kv *kv;
    msgpack_object *metadata;
    msgpack_unpacked result;
    Opentelemetry__Proto__Common__V1__KeyValue **buf;

    /* Maximum array size is the total number of root keys in metadata and record keys */
    array_size = event->body->via.map.size;

    /* log metadata (metada that comes from original Fluent Bit record ) */
    metadata = event->metadata;
    if (metadata) {
        array_size += metadata->via.map.size;
    }

    /*
     * Remove the keys from the record that were added to the log body and create a new output
     * buffer. If there are matches, meaning that a new output buffer was created, ret will
     * be FLB_TRUE, if no matches exists it returns FLB_FALSE.
     */
    if (ctx->logs_body_key_attributes == FLB_TRUE && ctx->mp_accessor && ra_match) {
        /*
         * if ra_match is not NULL, it means that the log body was populated with a key from the record
         * and the variable holds a reference to the record accessor that matched the key.
         *
         * Since 'likely' the mp_accessor context can have multiple record accessor patterns,
         * we need to make sure to remove 'only' the one that was used in the log body,
         * the approach we take is to disable all the patterns, enable the single one that
         * matched, process and then re-enable all of them.
         */
        flb_mp_accessor_set_active(ctx->mp_accessor, FLB_FALSE);

        /* Only active the one that matched */
        flb_mp_accessor_set_active_by_pattern(ctx->mp_accessor,
                                              ra_match->pattern,
                                              FLB_TRUE);

        /* Remove the undesired key */
        ret = flb_mp_accessor_keys_remove(ctx->mp_accessor, event->body, &out_buf, &out_size);
        if (ret) {
            msgpack_unpacked_init(&result);
            msgpack_unpack_next(&result, out_buf, out_size, &offset);

            array_size += result.data.via.map.size;
            unpacked = FLB_TRUE;
        }
        /* Enable all the mp_accessors */
        flb_mp_accessor_set_active(ctx->mp_accessor, FLB_TRUE);
    }

    /* allocate an array to hold the converted map entries */
    buf = flb_calloc(array_size, sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));
    if (!buf) {
        flb_errno();
        if (unpacked) {
            msgpack_unpacked_destroy(&result);
            flb_free(out_buf);
        }
        return -1;
    }

    /* pack log metadata */
    for (i = 0; i < metadata->via.map.size; i++) {
        kv = &metadata->via.map.ptr[i];
        buf[i] = msgpack_kv_to_otlp_any_value(kv);
        attr_count++;
    }

    /* remaining fields that were not added to log body */
    if (ctx->logs_body_key_attributes == FLB_TRUE && unpacked) {
        /* iterate the map and reference each elemento as an OTLP value */
        for (i = 0; i < result.data.via.map.size; i++) {
            kv = &result.data.via.map.ptr[i];
            buf[attr_count] = msgpack_kv_to_otlp_any_value(kv);
            attr_count++;
        }
        msgpack_unpacked_destroy(&result);
        flb_free(out_buf);
    }

    log_record->attributes = buf;
    log_record->n_attributes = attr_count;
    return 0;
}

static int flush_to_otel(struct opentelemetry_context *ctx,
                         struct flb_event_chunk *event_chunk,
                         Opentelemetry__Proto__Logs__V1__LogRecord **logs,
                         size_t log_count)
{
    int ret;
    void *body;
    unsigned len;

    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest export_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs scope_log;
    Opentelemetry__Proto__Logs__V1__ResourceLogs resource_log;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_logs[1];
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_logs[1];

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

    /* send post request to opentelemetry with content type application/x-protobuf */
    ret = http_post(ctx, body, len,
                    event_chunk->tag,
                    flb_sds_len(event_chunk->tag),
                    ctx->logs_uri);

    flb_free(body);

    return ret;
}

/* https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber */
static int is_valid_severity_text(const char *str, size_t str_len)
{
    if (str_len == 5) {
        if (strncmp("TRACE", str, 5) == 0 ||
            strncmp("DEBUG", str, 5) == 0 ||
            strncmp("ERROR", str, 5) == 0 ||
            strncmp("FATAL", str, 5) == 0) {
            return FLB_TRUE;
        }
    }
    else if (str_len == 4) {
        if (strncmp("INFO", str, 4) == 0||
            strncmp("WARN", str, 4) == 0) {
            return FLB_TRUE;
        }
    }
    return FLB_FALSE;
}
/* https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber */
static int is_valid_severity_number(uint64_t val)
{
    if (val >= 1 && val <= 24) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

static int append_v1_logs_metadata(struct opentelemetry_context *ctx,
                                   struct flb_log_event *event,
                                   Opentelemetry__Proto__Logs__V1__LogRecord  *log_record)
{
    struct flb_ra_value *ra_val;

    if (ctx == NULL || event == NULL || log_record == NULL) {
        return -1;
    }
    /* ObservedTimestamp */
    if (ctx->ra_observed_timestamp_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_observed_timestamp_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            log_record->observed_time_unix_nano = ra_val->o.via.u64;
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* Timestamp */
    if (ctx->ra_timestamp_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_timestamp_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            log_record->time_unix_nano = ra_val->o.via.u64;
            flb_ra_key_value_destroy(ra_val);
        }
        else {
            log_record->time_unix_nano = flb_time_to_nanosec(&event->timestamp);
        }
    }

    /* SeverityText */
    if (ctx->ra_severity_text_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_text_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_STR &&
            is_valid_severity_text(ra_val->o.via.str.ptr, ra_val->o.via.str.size) == FLB_TRUE) {
            log_record->severity_text = flb_calloc(1, ra_val->o.via.str.size+1);
            if (log_record->severity_text) {
                strncpy(log_record->severity_text, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
            }
            flb_ra_key_value_destroy(ra_val);
        }
        else {
            /* To prevent invalid free */
            log_record->severity_text = NULL;
        }
    }

    /* SeverityNumber */
    if (ctx->ra_severity_number_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_number_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER &&
            is_valid_severity_number(ra_val->o.via.u64) == FLB_TRUE) {
            log_record->severity_number = ra_val->o.via.u64;
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* TraceFlags */
    if (ctx->ra_trace_flags_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_trace_flags_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            log_record->flags = (uint32_t)ra_val->o.via.u64;
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* SpanId */
    if (ctx->ra_span_id_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_span_id_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_BIN) {
            log_record->span_id.data = flb_calloc(1, ra_val->o.via.bin.size);
            if (log_record->span_id.data) {
                memcpy(log_record->span_id.data, ra_val->o.via.bin.ptr, ra_val->o.via.bin.size);
                log_record->span_id.len = ra_val->o.via.bin.size;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* TraceId */
    if (ctx->ra_trace_id_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_trace_id_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_BIN) {
            log_record->trace_id.data = flb_calloc(1, ra_val->o.via.bin.size);
            if (log_record->trace_id.data) {
                memcpy(log_record->trace_id.data, ra_val->o.via.bin.ptr, ra_val->o.via.bin.size);
                log_record->trace_id.len = ra_val->o.via.bin.size;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* Attributes */
    if (ctx->ra_attributes_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_attributes_metadata, *event->metadata);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_MAP) {
            if (log_record->attributes != NULL) {
                otlp_kvarray_destroy(log_record->attributes,
                                     log_record->n_attributes);
            }
            log_record->attributes = msgpack_map_to_otlp_kvarray(&ra_val->o, &log_record->n_attributes);
            flb_ra_key_value_destroy(ra_val);
        }
    }

    return 0;
}

static int append_v1_logs_message(struct opentelemetry_context *ctx,
                                   struct flb_log_event *event,
                                   Opentelemetry__Proto__Logs__V1__LogRecord  *log_record)
{
    struct flb_ra_value *ra_val;

    if (ctx == NULL || event == NULL || log_record == NULL) {
        return -1;
    }

        /* SeverityText */
    if (ctx->ra_severity_text_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_text_message, *event->body);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_STR) {
            if(is_valid_severity_text(ra_val->o.via.str.ptr, ra_val->o.via.str.size) == FLB_TRUE){
                log_record->severity_text = flb_calloc(1, ra_val->o.via.str.size+1);
                if (log_record->severity_text) {
                    strncpy(log_record->severity_text, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
                }
                flb_ra_key_value_destroy(ra_val);
            }else{
                flb_plg_warn(ctx->ins, "Unable to process %s. Invalid Severity Text.\n", ctx->ra_severity_text_message->pattern);
                log_record->severity_text = NULL;
            }
        }
        else {
            /* To prevent invalid free */
            log_record->severity_text = NULL;
        }
    }

    /* SeverityNumber */
    if (ctx->ra_severity_number_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_number_metadata, *event->body);
        if (ra_val != NULL && ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER &&
            is_valid_severity_number(ra_val->o.via.u64) == FLB_TRUE) {
            log_record->severity_number = ra_val->o.via.u64;
            flb_ra_key_value_destroy(ra_val);
        }
    }else if(ctx->ra_severity_text_message){
        //TODO get sev number based off sev text
    }

    /* SpanId */
    if (ctx->ra_span_id_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_span_id_message, *event->body);
        if (ra_val != NULL) {
            if(ra_val->o.type == MSGPACK_OBJECT_BIN){
                log_record->span_id.data = flb_calloc(1, ra_val->o.via.bin.size);
                if (log_record->span_id.data) {
                    memcpy(log_record->span_id.data, ra_val->o.via.bin.ptr, ra_val->o.via.bin.size);
                    log_record->span_id.len = ra_val->o.via.bin.size;
                }
            }else if(ra_val->o.type == MSGPACK_OBJECT_STR){
                log_record->span_id.data = flb_calloc(8, sizeof(uint8_t));
                if (log_record->span_id.data) {
                    // Convert to a byte array
                    uint8_t val[8];
                    size_t count;
                    for(count = 0; count < sizeof val/sizeof *val; count++ ){
                        sscanf(ra_val->o.via.str.ptr, "%2hhx", &val[count]);
                        ra_val->o.via.str.ptr+=2;
                    }
                    memcpy(log_record->span_id.data, val, sizeof(val));
                    log_record->span_id.len = sizeof(val);
                }
            }else{
                flb_plg_warn(ctx->ins, "Unable to process %s. Unsupported data type.\n", ctx->ra_span_id_message->pattern);
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* TraceId */
    if (ctx->ra_trace_id_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_trace_id_message, *event->body);
        if (ra_val != NULL) {
            if(ra_val->o.type == MSGPACK_OBJECT_BIN){
                log_record->trace_id.data = flb_calloc(1, ra_val->o.via.bin.size);
                if (log_record->trace_id.data) {
                    memcpy(log_record->trace_id.data, ra_val->o.via.bin.ptr, ra_val->o.via.bin.size);
                    log_record->trace_id.len = ra_val->o.via.bin.size;
                }
            }else if(ra_val->o.type == MSGPACK_OBJECT_STR){
                log_record->trace_id.data = flb_calloc(16, sizeof(uint8_t));
                if (log_record->trace_id.data) {
                    // Convert from hexdec string to a 16 byte array
                    uint8_t val[16];
                    size_t count;
                    for(count = 0; count < sizeof val/sizeof *val; count++ ){
                        sscanf(ra_val->o.via.str.ptr, "%2hhx", &val[count]);
                        ra_val->o.via.str.ptr+=2;
                    }
                    memcpy(log_record->trace_id.data, val, sizeof(val));
                    log_record->trace_id.len = sizeof(val);
                }
            }else{
                flb_plg_warn(ctx->ins, "Unable to process %s. Unsupported data type.\n", ctx->ra_trace_id_message->pattern);
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    return 0;
}

static int process_logs(struct flb_event_chunk *event_chunk,
                        struct flb_output_flush *out_flush,
                        struct flb_input_instance *ins, void *out_context,
                        struct flb_config *config)
{
    int                                         ret;
    size_t                                      i;
    size_t                                      log_record_count;
    Opentelemetry__Proto__Logs__V1__LogRecord **log_record_list;
    Opentelemetry__Proto__Logs__V1__LogRecord  *log_records;
    struct flb_log_event_decoder               *decoder;
    struct flb_log_event                        event;
    struct opentelemetry_context               *ctx;
    struct flb_record_accessor *ra_match;

    ctx = (struct opentelemetry_context *) out_context;

    log_record_list = (Opentelemetry__Proto__Logs__V1__LogRecord **)
        flb_calloc(ctx->batch_size, sizeof(Opentelemetry__Proto__Logs__V1__LogRecord *));
    if (!log_record_list) {
        flb_errno();
        return -1;
    }

    log_records = (Opentelemetry__Proto__Logs__V1__LogRecord *)
        flb_calloc(ctx->batch_size,
                   sizeof(Opentelemetry__Proto__Logs__V1__LogRecord));

    if (!log_records) {
        flb_errno();
        flb_free(log_record_list);
        return -2;
    }

    for (i = 0 ; i < ctx->batch_size ; i++) {
        log_record_list[i] = &log_records[i];
    }

    decoder = flb_log_event_decoder_create((char *) event_chunk->data, event_chunk->size);
    if (decoder == NULL) {
        flb_plg_error(ctx->ins, "could not initialize record decoder");
        flb_free(log_record_list);
        flb_free(log_records);
        return -1;
    }

    log_record_count = 0;

    ret = FLB_OK;
    while (flb_log_event_decoder_next(decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        ra_match = NULL;
        opentelemetry__proto__logs__v1__log_record__init(&log_records[log_record_count]);

        /*
         * Set the record body by using the logic defined in the configuration by
         * the 'logs_body_key' properties.
         *
         * Note that the reference set in `out_body_parent_key` is the parent/root key that holds the content
         * that was discovered. We get that reference so we can easily filter it out when composing
         * the final list of attributes.
         */
        ret = log_record_set_body(ctx, &log_records[log_record_count], &event, &ra_match);
        if (ret == -1) {
            /* the only possible fail path is a problem with a memory allocation, let's suggest a FLB_RETRY */
            ret = FLB_RETRY;
            break;
        }

        /* set attributes from metadata and remaining fields from the main record */
        ret = log_record_set_attributes(ctx, &log_records[log_record_count], &event, ra_match);
        if (ret == -1) {
            /* as before, it can only fail on a memory allocation */
            ret = FLB_RETRY;
            break;
        }

        append_v1_logs_metadata(ctx, &event, &log_records[log_record_count]);

        append_v1_logs_message(ctx, &event, &log_records[log_record_count]);

        ret = FLB_OK;

        log_records[log_record_count].time_unix_nano = flb_time_to_nanosec(&event.timestamp);
        log_record_count++;

        if (log_record_count >= ctx->batch_size) {
            ret = flush_to_otel(ctx, event_chunk, log_record_list, log_record_count);
            clear_array(log_record_list, log_record_count);
            log_record_count = 0;
        }
    }

    flb_log_event_decoder_destroy(decoder);

    if (log_record_count > 0 && ret == FLB_OK) {
        ret = flush_to_otel(ctx,
                            event_chunk,
                            log_record_list,
                            log_record_count);

        clear_array(log_record_list, log_record_count);
    }

    flb_free(log_record_list);
    flb_free(log_records);

    return ret;
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
        result = http_post(ctx, buf, flb_sds_len(buf),
                           event_chunk->tag,
                           flb_sds_len(event_chunk->tag),
                           ctx->traces_uri);

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
            result = process_logs(event_chunk, out_flush, ins, out_context, config);
        }
        else if (event_chunk->type == FLB_INPUT_TRACES){
            result = process_traces(event_chunk, out_flush, ins, out_context, config);
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
      FLB_CONFIG_MAP_INT, "batch_size", DEFAULT_LOG_RECORD_BATCH_SIZE,
      0, FLB_TRUE, offsetof(struct opentelemetry_context, batch_size),
      "Set the maximum number of log records to be flushed at a time"
    },
    {
     FLB_CONFIG_MAP_STR, "compress", NULL,
     0, FLB_FALSE, 0,
     "Set payload compression mechanism. Option available is 'gzip'"
    },
    /*
     * Logs Properties
     * ---------------
     */
    {
     FLB_CONFIG_MAP_STR, "logs_uri", "/v1/logs",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, logs_uri),
     "Specify an optional HTTP URI for the target OTel endpoint."
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
     FLB_CONFIG_MAP_BOOL, "log_response_payload", "true",
     0, FLB_TRUE, offsetof(struct opentelemetry_context, log_response_payload),
     "Specify if the response paylod should be logged or not"
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
    .event_type  = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS | FLB_OUTPUT_TRACES,
    .flags       = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
