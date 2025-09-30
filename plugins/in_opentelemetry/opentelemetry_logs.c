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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_opentelemetry.h>
#include <fluent-otel-proto/fluent-otel.h>


#include "opentelemetry.h"
#include "opentelemetry_utils.h"

/*
 * OTLP encoding functions to pack the log records as msgpack
 * ----------------------------------------------------------
 */
static int otlp_pack_any_value(msgpack_packer *mp_pck, Opentelemetry__Proto__Common__V1__AnyValue *body);

static int otel_pack_string(msgpack_packer *mp_pck, char *str)
{
    return msgpack_pack_str_with_body(mp_pck, str, strlen(str));
}

static int otel_pack_bool(msgpack_packer *mp_pck, bool val)
{
    if (val) {
        return msgpack_pack_true(mp_pck);
    }
    else {
        return msgpack_pack_false(mp_pck);
    }
}

static int otel_pack_int(msgpack_packer *mp_pck, int val)
{
    return msgpack_pack_int64(mp_pck, val);
}

static int otel_pack_double(msgpack_packer *mp_pck, double val)
{
    return msgpack_pack_double(mp_pck, val);
}

static int otel_pack_kvarray(msgpack_packer *mp_pck,
                             Opentelemetry__Proto__Common__V1__KeyValue **kv_array,
                             size_t kv_count)
{
    int result;
    int index;

    result = msgpack_pack_map(mp_pck, kv_count);

    if (result != 0) {
        return result;
    }

    for (index = 0; index < kv_count && result == 0; index++) {
        result = otel_pack_string(mp_pck, kv_array[index]->key);

        if(result == 0) {
           result = otlp_pack_any_value(mp_pck, kv_array[index]->value);
        }
    }

    return result;
}

static int otel_pack_kvlist(msgpack_packer *mp_pck,
                            Opentelemetry__Proto__Common__V1__KeyValueList *kv_list)
{
    int kv_index;
    int ret;
    char *key;
    Opentelemetry__Proto__Common__V1__AnyValue *value;

    ret = msgpack_pack_map(mp_pck, kv_list->n_values);
    if (ret != 0) {
        return ret;
    }

    for (kv_index = 0; kv_index < kv_list->n_values && ret == 0; kv_index++) {
        key = kv_list->values[kv_index]->key;
        value = kv_list->values[kv_index]->value;

        ret = otel_pack_string(mp_pck, key);

        if(ret == 0) {
           ret = otlp_pack_any_value(mp_pck, value);
        }
    }

    return ret;
}

static int otel_pack_array(msgpack_packer *mp_pck,
                           Opentelemetry__Proto__Common__V1__ArrayValue *array)
{
    int ret;
    int array_index;

    ret = msgpack_pack_array(mp_pck, array->n_values);

    if (ret != 0) {
        return ret;
    }

    for (array_index = 0; array_index < array->n_values && ret == 0; array_index++) {
        ret = otlp_pack_any_value(mp_pck, array->values[array_index]);
    }

    return ret;
}

static int otel_pack_bytes(msgpack_packer *mp_pck,
                           ProtobufCBinaryData bytes)
{
    return msgpack_pack_bin_with_body(mp_pck, bytes.data, bytes.len);
}

static int otlp_pack_any_value(msgpack_packer *mp_pck,
                               Opentelemetry__Proto__Common__V1__AnyValue *body)
{
    int result;

    result = -2;

    if (body == NULL) {
        msgpack_pack_nil(mp_pck);
        return 0;
    }

    switch(body->value_case){
        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE:
            result = otel_pack_string(mp_pck, body->string_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE:
            result =  otel_pack_bool(mp_pck, body->bool_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE:
            result = otel_pack_int(mp_pck, body->int_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE:
            result = otel_pack_double(mp_pck, body->double_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE:
            result = otel_pack_array(mp_pck, body->array_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE:
            result = otel_pack_kvlist(mp_pck, body->kvlist_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE:
            result = otel_pack_bytes(mp_pck, body->bytes_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE__NOT_SET:
            /* treat an unset value as null */
            result = msgpack_pack_nil(mp_pck);
            break;

        default:
            break;
    }

    if (result == -2) {
        flb_error("[otel]: invalid value type in pack_any_value");
        result = -1;
    }

    return result;
}

/* https://opentelemetry.io/docs/specs/otel/logs/data-model/#log-and-event-record-definition */
static int otel_pack_v1_metadata(struct flb_opentelemetry *ctx,
                                 msgpack_packer *mp_pck,
                                 struct Opentelemetry__Proto__Logs__V1__LogRecord *log_record,
                                 Opentelemetry__Proto__Resource__V1__Resource *resource,
                                 Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    int ret;
    int len;
    struct flb_mp_map_header mh;
    struct flb_mp_map_header otlp_mh;

    flb_mp_map_header_init(&otlp_mh, mp_pck);

    len = flb_sds_len(ctx->logs_metadata_key);

    /* otlp key start */
    flb_mp_map_header_append(&otlp_mh);

    msgpack_pack_str(mp_pck, len);
    msgpack_pack_str_body(mp_pck, ctx->logs_metadata_key, len);

    flb_mp_map_header_init(&mh, mp_pck);

    if (log_record->observed_time_unix_nano != 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 18);
        msgpack_pack_str_body(mp_pck, "observed_timestamp", 18);
        msgpack_pack_uint64(mp_pck, log_record->observed_time_unix_nano);
    }

    /* Value of 0 indicates unknown or missing timestamp. */
    if (log_record->time_unix_nano != 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 9);
        msgpack_pack_str_body(mp_pck, "timestamp", 9);
        msgpack_pack_uint64(mp_pck, log_record->time_unix_nano);
    }

    /* https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber */
    if (log_record->severity_number >= 1 && log_record->severity_number <= 24) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 15);
        msgpack_pack_str_body(mp_pck, "severity_number", 15);
        msgpack_pack_uint64(mp_pck, log_record->severity_number);
    }

    if (log_record->severity_text != NULL && strlen(log_record->severity_text) > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 13);
        msgpack_pack_str_body(mp_pck, "severity_text", 13);
        msgpack_pack_str(mp_pck, strlen(log_record->severity_text));
        msgpack_pack_str_body(mp_pck, log_record->severity_text, strlen(log_record->severity_text));
    }

    if (log_record->n_attributes > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 10);
        msgpack_pack_str_body(mp_pck, "attributes", 10);
        ret = otel_pack_kvarray(mp_pck,
                                log_record->attributes,
                                log_record->n_attributes);
        if (ret != 0) {
            return ret;
        }
    }

    if (log_record->trace_id.len > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 8);
        msgpack_pack_str_body(mp_pck, "trace_id", 8);
        ret = otel_pack_bytes(mp_pck, log_record->trace_id);
        if (ret != 0) {
            return ret;
        }
    }

    if (log_record->span_id.len > 0) {
        flb_mp_map_header_append(&mh);
        msgpack_pack_str(mp_pck, 7);
        msgpack_pack_str_body(mp_pck, "span_id", 7);
        ret = otel_pack_bytes(mp_pck, log_record->span_id);
        if (ret != 0) {
            return ret;
        }
    }

    flb_mp_map_header_append(&mh);
    msgpack_pack_str(mp_pck, 11);
    msgpack_pack_str_body(mp_pck, "trace_flags", 11);
    msgpack_pack_uint8(mp_pck, (uint8_t) log_record->flags & 0xff);

    flb_mp_map_header_end(&mh);

    /* otlp key end */
    flb_mp_map_header_end(&otlp_mh);

    return 0;
}

static int binary_payload_to_msgpack(struct flb_opentelemetry *ctx,
                                     struct flb_log_event_encoder *encoder,
                                     char *tag, size_t tag_len,
                                     uint8_t *in_buf,
                                     size_t in_size)
{
    int ret;
    int len;
    int resource_logs_index;
    int scope_log_index;
    int log_record_index;
    char *logs_body_key;
    struct flb_mp_map_header mh;
    struct flb_mp_map_header mh_tmp;
    struct flb_time tm;

    /* record buffer and packer */
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;

    /* metadata buffer and packer */
    msgpack_sbuffer mp_sbuf_meta;
    msgpack_packer  mp_pck_meta;

    /* OTel proto suff */
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *input_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **scope_logs;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;
    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope;

    Opentelemetry__Proto__Logs__V1__ResourceLogs **resource_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__LogRecord **log_records;
    Opentelemetry__Proto__Resource__V1__Resource *resource;

    /* initialize msgpack buffers */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_sbuffer_init(&mp_sbuf_meta);
    msgpack_packer_init(&mp_pck_meta, &mp_sbuf_meta, msgpack_sbuffer_write);

    /* unpack logs from protobuf payload */
    input_logs = opentelemetry__proto__collector__logs__v1__export_logs_service_request__unpack(NULL, in_size, in_buf);
    if (input_logs == NULL) {
        flb_plg_warn(ctx->ins, "failed to unpack input logs from OpenTelemetry payload");
        ret = -1;
        goto binary_payload_to_msgpack_end;
    }

    resource_logs = input_logs->resource_logs;
    if (resource_logs == NULL) {
        flb_plg_warn(ctx->ins, "no resource logs found");
        ret = -1;
        goto binary_payload_to_msgpack_end;
    }

    for (resource_logs_index = 0; resource_logs_index < input_logs->n_resource_logs; resource_logs_index++) {
        resource_log = resource_logs[resource_logs_index];

        resource = resource_log->resource;
        scope_logs = resource_log->scope_logs;

        if (resource_log->n_scope_logs > 0 && scope_logs == NULL) {
            flb_plg_warn(ctx->ins, "no scope logs found");
            ret = -1;
            goto binary_payload_to_msgpack_end;
        }

        for (scope_log_index = 0; scope_log_index < resource_log->n_scope_logs; scope_log_index++) {
            scope_log = scope_logs[scope_log_index];
            log_records = scope_log->log_records;

            if (log_records == NULL) {
                flb_plg_warn(ctx->ins, "no log records found");
                ret = -1;
                goto binary_payload_to_msgpack_end;
            }

            flb_log_event_encoder_group_init(encoder);

            /* pack schema (internal) */
            ret = flb_log_event_encoder_append_metadata_values(encoder,
                                                               FLB_LOG_EVENT_STRING_VALUE("schema", 6),
                                                               FLB_LOG_EVENT_STRING_VALUE("otlp", 4),
                                                               FLB_LOG_EVENT_STRING_VALUE("resource_id", 11),
                                                               FLB_LOG_EVENT_INT64_VALUE(resource_logs_index),
                                                               FLB_LOG_EVENT_STRING_VALUE("scope_id", 8),
                                                               FLB_LOG_EVENT_INT64_VALUE(scope_log_index));


            flb_mp_map_header_init(&mh, &mp_pck);

            /* Resource */
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(&mp_pck, 8);
            msgpack_pack_str_body(&mp_pck, "resource", 8);

            flb_mp_map_header_init(&mh_tmp, &mp_pck);
            if (resource) {
                /* look for OTel resource attributes */
                if (resource->n_attributes > 0 && resource->attributes) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "attributes", 10);

                    ret = otel_pack_kvarray(&mp_pck,
                                            resource->attributes,
                                            resource->n_attributes);
                    if (ret != 0) {
                        return ret;
                    }
                }

                if (resource->dropped_attributes_count > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 24);
                    msgpack_pack_str_body(&mp_pck, "dropped_attributes_count", 24);
                    msgpack_pack_uint64(&mp_pck, resource->dropped_attributes_count);
                }

                if (resource_log->schema_url) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "schema_url", 10);

                    len = strlen(resource_log->schema_url);
                    msgpack_pack_str(&mp_pck, len);
                    msgpack_pack_str_body(&mp_pck, resource_log->schema_url, len);
                }
            }
            flb_mp_map_header_end(&mh_tmp);

            /* scope */
            flb_mp_map_header_append(&mh);
            msgpack_pack_str(&mp_pck, 5);
            msgpack_pack_str_body(&mp_pck, "scope", 5);

            /* Scope */
            scope = scope_log->scope;

            if (scope && (scope->name || scope->version || scope->n_attributes > 0)) {
                flb_mp_map_header_init(&mh_tmp, &mp_pck);

                if (scope_log->schema_url && strlen(scope_log->schema_url) > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "schema_url", 10);

                    len = strlen(scope_log->schema_url);
                    msgpack_pack_str(&mp_pck, len);
                    msgpack_pack_str_body(&mp_pck, scope_log->schema_url, len);
                }

                if (scope->name && strlen(scope->name) > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 4);
                    msgpack_pack_str_body(&mp_pck, "name", 4);

                    len = strlen(scope->name);
                    msgpack_pack_str(&mp_pck, len);
                    msgpack_pack_str_body(&mp_pck, scope->name, len);
                }
                if (scope->version && strlen(scope->version) > 0) {
                    flb_mp_map_header_append(&mh_tmp);

                    msgpack_pack_str(&mp_pck, 7);
                    msgpack_pack_str_body(&mp_pck, "version", 7);

                    len = strlen(scope->version);
                    msgpack_pack_str(&mp_pck, len);
                    msgpack_pack_str_body(&mp_pck, scope->version, len);
                }

                if (scope->n_attributes > 0 && scope->attributes) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 10);
                    msgpack_pack_str_body(&mp_pck, "attributes", 10);
                    ret = otel_pack_kvarray(&mp_pck,
                                            scope->attributes,
                                            scope->n_attributes);
                    if (ret != 0) {
                        return ret;
                    }
                }

                if (scope->dropped_attributes_count > 0) {
                    flb_mp_map_header_append(&mh_tmp);
                    msgpack_pack_str(&mp_pck, 24);
                    msgpack_pack_str_body(&mp_pck, "dropped_attributes_count", 24);
                    msgpack_pack_uint64(&mp_pck, scope->dropped_attributes_count);
                }

                flb_mp_map_header_end(&mh_tmp);
            }
            else {
                /* set an empty scope */
                msgpack_pack_map(&mp_pck, 0);
            }

            flb_mp_map_header_end(&mh);

            ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                            encoder,
                            mp_sbuf.data,
                            mp_sbuf.size);
            if (ret != FLB_EVENT_ENCODER_SUCCESS) {
                flb_plg_error(ctx->ins, "could not set group content metadata");
                goto binary_payload_to_msgpack_end;
            }

            flb_log_event_encoder_group_header_end(encoder);

            msgpack_sbuffer_clear(&mp_sbuf);

            for (log_record_index=0; log_record_index < scope_log->n_log_records; log_record_index++) {
                ret = flb_log_event_encoder_begin_record(encoder);

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    if (log_records[log_record_index]->time_unix_nano > 0) {
                        flb_time_from_uint64(&tm, log_records[log_record_index]->time_unix_nano);
                        ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
                    }
                    else if (log_records[log_record_index]->observed_time_unix_nano > 0) {
                        flb_time_from_uint64(&tm, log_records[log_record_index]->observed_time_unix_nano);
                        ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
                    }
                    else {
                        flb_time_get(&tm);
                        ret = flb_log_event_encoder_set_timestamp(encoder, &tm);
                    }
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                     msgpack_sbuffer_clear(&mp_sbuf_meta);
                     ret = otel_pack_v1_metadata(ctx, &mp_pck_meta, log_records[log_record_index], resource, scope_log->scope);
                     if (ret != 0) {
                        flb_plg_error(ctx->ins, "failed to convert log record");
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        ret = flb_log_event_encoder_set_metadata_from_raw_msgpack(
                                encoder,
                                mp_sbuf_meta.data,
                                mp_sbuf_meta.size);
                    }

                    msgpack_sbuffer_clear(&mp_sbuf_meta);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = otlp_pack_any_value(
                            &mp_pck,
                            log_records[log_record_index]->body);

                    if (ret != 0) {
                        flb_plg_error(ctx->ins, "failed to convert log record body");
                        ret = FLB_EVENT_ENCODER_ERROR_SERIALIZATION_FAILURE;
                    }
                    else {
                        if (ctx->logs_body_key == NULL &&
                            log_records[log_record_index]->body != NULL &&
                            log_records[log_record_index]->body->value_case ==
                            OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE) {
                            ret = flb_log_event_encoder_set_body_from_raw_msgpack(
                                    encoder,
                                    mp_sbuf.data,
                                    mp_sbuf.size);
                        }
                        else {
                            logs_body_key = ctx->logs_body_key;
                            if (logs_body_key == NULL) {
                                logs_body_key = "log";
                            }
                            ret = flb_log_event_encoder_append_body_values(
                                    encoder,
                                    FLB_LOG_EVENT_CSTRING_VALUE(logs_body_key),
                                    FLB_LOG_EVENT_MSGPACK_RAW_VALUE(mp_sbuf.data, mp_sbuf.size));
                        }
                    }

                    msgpack_sbuffer_clear(&mp_sbuf);
                }

                if (ret == FLB_EVENT_ENCODER_SUCCESS) {
                    ret = flb_log_event_encoder_commit_record(encoder);
                }
                else {
                    flb_plg_error(ctx->ins, "marshalling error");
                    goto binary_payload_to_msgpack_end;
                }
            }

            flb_log_event_encoder_group_end(encoder);

        }
    }

 binary_payload_to_msgpack_end:
    msgpack_sbuffer_destroy(&mp_sbuf);
    msgpack_sbuffer_destroy(&mp_sbuf_meta);
    if (input_logs) {
        opentelemetry__proto__collector__logs__v1__export_logs_service_request__free_unpacked(
                                            input_logs, NULL);
    }

    if (ret != 0) {
        return -1;
    }

    return 0;
}

/*
 * Main function used from opentelemetry_prot.c to process logs either in JSON or Protobuf format.
 * -----------------------------------------------------------------------------------------------
 */
int opentelemetry_process_logs(struct flb_opentelemetry *ctx,
                               flb_sds_t content_type,
                               flb_sds_t tag,
                               size_t tag_len,
                               void *data, size_t size)
{
    int ret = -1;
    int is_proto = FLB_FALSE; /* default to JSON */
    int error_status = 0;
    char *buf;
    uint8_t *payload;
    uint64_t payload_size;
    struct flb_log_event_encoder *encoder;

    buf = (char *) data;
    payload = data;
    payload_size = size;

    /* Detect the type of payload */
    if (content_type) {
        if (strcasecmp(content_type, "application/json") == 0) {
            if (buf[0] != '{') {
                flb_plg_error(ctx->ins, "Invalid JSON payload");
                return -1;
            }
            is_proto = FLB_FALSE;
        }
        else if (strcasecmp(content_type, "application/protobuf") == 0 ||
                 strcasecmp(content_type, "application/grpc") == 0 ||
                 strcasecmp(content_type, "application/x-protobuf") == 0) {
            is_proto = FLB_TRUE;
        }
        else {
            flb_plg_error(ctx->ins, "Unsupported content type %s", content_type);
            return -1;
        }
    }

    encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_FLUENT_BIT_V2);
    if (encoder == NULL) {
        return -1;
    }

    if (is_proto == FLB_TRUE) {
        ret = binary_payload_to_msgpack(ctx, encoder,
                                        tag, tag_len,
                                        (uint8_t *) payload, payload_size);
        if (ret < 0) {
            flb_plg_error(ctx->ins, "failed to process logs from protobuf payload");
        }
    }
    else {
        ret = flb_opentelemetry_logs_json_to_msgpack(encoder,
                                                     (const char *) payload, payload_size,
                                                     ctx->logs_body_key,
                                                     &error_status);
        if (ret != 0) {
            /* we are printing the error for now, let's see what is the user's preference later */
            flb_plg_error(ctx->ins, "failed to process logs from JSON payload (%i) %s",
                          error_status,
                          flb_opentelemetry_error_to_string(error_status));
        }

    }

    if (ret >= 0) {
        ret = flb_input_log_append(ctx->ins,
                                   tag,
                                   flb_sds_len(tag),
                                   encoder->output_buffer,
                                   encoder->output_length);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to append logs to the input buffer");
        }
    }

    flb_log_event_encoder_destroy(encoder);
    return ret;
}
