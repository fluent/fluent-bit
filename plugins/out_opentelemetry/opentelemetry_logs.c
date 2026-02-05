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
#include <fluent-bit/flb_snappy.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_ra_key.h>
#include <fluent-bit/flb_gzip.h>

#include <fluent-otel-proto/fluent-otel.h>

#include "opentelemetry.h"
#include "opentelemetry_conf.h"
#include "opentelemetry_utils.h"

#define RESOURCE_LOGS_INITIAL_CAPACITY 256
#define SCOPE_LOGS_INITIAL_CAPACITY    100

static int hex_to_int(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }

    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }

    return -1;
}

/* convert an hex string to the expected id (16 bytes) */
static int hex_to_id(char *str, int len, unsigned char *out_buf, int out_size)
{
    int i;
    int high;
    int low;

    if (len % 2 != 0) {
        return -1;
    }

    for (i = 0; i < len; i += 2) {
        if (!isxdigit(str[i]) || !isxdigit(str[i + 1])) {
            return -1;
        }

        high = hex_to_int(str[i]);
        low = hex_to_int(str[i + 1]);

        if (high == -1 || low == -1) {
            return -1;
        }

        out_buf[i / 2] = (high << 4) | low;
    }

    return 0;
}

/* https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber */
static int is_valid_severity_number(uint64_t val)
{
    if (val >= 1 && val <= 24) {
        return FLB_TRUE;
    }
    return FLB_FALSE;
}

/*
 * From a group record, extract it metadata and validate if it has a valid OTLP schema and check that
 * resource_id is set. On success it returns the resource_id, otherwise it returns -1.
 */
static int get_otlp_group_metadata(struct opentelemetry_context *ctx, struct flb_log_event *event,
                                   int64_t *resource_id, int64_t *scope_id)
{
    struct flb_ra_value *ra_val;

    /*
     * $schema == 'otlp'
     */
    ra_val = flb_ra_get_value_object(ctx->ra_meta_schema, *event->metadata);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_STR) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    if (ra_val->o.via.str.size != 4) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    if (strncmp(ra_val->o.via.str.ptr, "otlp", ra_val->o.via.str.size) != 0) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }
    flb_ra_key_value_destroy(ra_val);


    /*
     * $resource_id
     */
    ra_val = flb_ra_get_value_object(ctx->ra_meta_resource_id, *event->metadata);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }
    *resource_id = ra_val->o.via.i64;
    flb_ra_key_value_destroy(ra_val);

    /*
     * $scope_id
     */
    ra_val = flb_ra_get_value_object(ctx->ra_meta_scope_id, *event->metadata);
    if (ra_val == NULL) {
        return -1;
    }
    if (ra_val->o.type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }
    *scope_id = ra_val->o.via.i64;

    flb_ra_key_value_destroy(ra_val);
    return 0;
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

    /* log metadata (metadata that comes from original Fluent Bit record) */
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

        if (kv->key.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        /* skip internal otlp metadata */
        if (kv->key.via.str.size == 4 && strncmp(kv->key.via.str.ptr, "otlp", 4) == 0) {
            continue;
        }

        buf[attr_count] = msgpack_kv_to_otlp_any_value(kv);
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

static int pack_trace_id(struct opentelemetry_context *ctx,
                         Opentelemetry__Proto__Logs__V1__LogRecord *log_record,
                         struct flb_ra_value *ra_val)
{
    int ret;

    if (ra_val->o.type == MSGPACK_OBJECT_BIN) {
        log_record->trace_id.data = flb_calloc(1, ra_val->o.via.bin.size);
        if (!log_record->trace_id.data) {
            return -1;
        }
        memcpy(log_record->trace_id.data, ra_val->o.via.bin.ptr, ra_val->o.via.bin.size);
        log_record->trace_id.len = ra_val->o.via.bin.size;
    }
    else if (ra_val->o.type == MSGPACK_OBJECT_STR) {
        if (ra_val->o.via.str.size > 32) {
            return -1;
        }

        log_record->trace_id.data = flb_calloc(1, 16);
        if (!log_record->trace_id.data) {
            flb_errno();
            return -1;
        }

        ret = hex_to_id((char *) ra_val->o.via.str.ptr, ra_val->o.via.str.size,
                        log_record->trace_id.data, 16);
        if (ret == 0) {
            log_record->trace_id.len = 16;
            return 0;
        }

        flb_plg_warn(ctx->ins, "invalid trace_id format");
        flb_free(log_record->trace_id.data);
        log_record->trace_id.data = NULL;
        log_record->trace_id.len = 0;
    }
    else {
        flb_plg_warn(ctx->ins, "invalid trace_id type");
    }

    return -1;
}

static int pack_span_id(struct opentelemetry_context *ctx,
                        Opentelemetry__Proto__Logs__V1__LogRecord *log_record,
                        struct flb_ra_value *ra_val)
{
    if (ra_val->o.type == MSGPACK_OBJECT_BIN) {
        log_record->span_id.data = flb_calloc(1, ra_val->o.via.bin.size);
        if (!log_record->span_id.data) {
            return -1;
        }
        memcpy(log_record->span_id.data, ra_val->o.via.bin.ptr, ra_val->o.via.bin.size);
        log_record->span_id.len = ra_val->o.via.bin.size;
    }
    else if (ra_val->o.type == MSGPACK_OBJECT_STR) {
        if (ra_val->o.via.str.size > 16) {
            return -1;
        }

        log_record->span_id.data = flb_calloc(1, 8);
        if (!log_record->span_id.data) {
            flb_errno();
            return -1;
        }

        hex_to_id((char *) ra_val->o.via.str.ptr, ra_val->o.via.str.size,
                  log_record->span_id.data, 8);
        log_record->span_id.len = 8;
    }
    else {
        flb_plg_warn(ctx->ins, "invalid span_id type");
    }

    return 0;
}

static int append_v1_logs_metadata_and_fields(struct opentelemetry_context *ctx,
                                              struct flb_log_event *event,
                                              Opentelemetry__Proto__Logs__V1__LogRecord  *log_record)
{
    int ret;
    int span_id_set = FLB_FALSE;
    int trace_id_set = FLB_FALSE;
    int severity_text_set = FLB_FALSE;
    int severity_number_set = FLB_FALSE;
    int trace_flags_set = FLB_FALSE;
    int event_name_set = FLB_FALSE;
    size_t attr_count = 0;
    struct flb_ra_value *ra_val;
    Opentelemetry__Proto__Common__V1__KeyValue **attrs = NULL;

    if (ctx == NULL || event == NULL || log_record == NULL) {
        return -1;
    }

    /* ObservedTimestamp */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_observed_ts, *event->metadata);
    if (ra_val != NULL) {
        if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            log_record->observed_time_unix_nano = ra_val->o.via.u64;
        }
        flb_ra_key_value_destroy(ra_val);
    }
    else if (ctx->ra_observed_timestamp_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_observed_timestamp_metadata, *event->metadata);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                log_record->observed_time_unix_nano = ra_val->o.via.u64;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* Timestamp */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_timestamp, *event->metadata);
    if (ra_val != NULL) {
        if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            log_record->time_unix_nano = ra_val->o.via.u64;
        }
        flb_ra_key_value_destroy(ra_val);
    }
    else if (ctx->ra_timestamp_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_timestamp_metadata, *event->metadata);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                log_record->time_unix_nano = ra_val->o.via.u64;
            }
            flb_ra_key_value_destroy(ra_val);
        }
        else {
            log_record->time_unix_nano = flb_time_to_nanosec(&event->timestamp);
        }
    }

    /* SeverityNumber */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_severity_number, *event->metadata);
    if (ra_val != NULL) {
        if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER && is_valid_severity_number(ra_val->o.via.u64)) {
            log_record->severity_number = ra_val->o.via.u64;
            severity_number_set = FLB_TRUE;
        }
        flb_ra_key_value_destroy(ra_val);
    }

    if (!severity_number_set && ctx->ra_severity_number_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_number_metadata, *event->metadata);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER && is_valid_severity_number(ra_val->o.via.u64)) {
                log_record->severity_number = ra_val->o.via.u64;
                severity_number_set = FLB_TRUE;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    if (!severity_number_set && ctx->ra_severity_number_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_number_message, *event->body);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER && is_valid_severity_number(ra_val->o.via.u64)) {
                log_record->severity_number = ra_val->o.via.u64;
                severity_number_set = FLB_TRUE;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* SeverityText */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_severity_text, *event->metadata);
    if (ra_val != NULL) {
        if (ra_val->o.type == MSGPACK_OBJECT_STR) {
            log_record->severity_text = flb_calloc(1, ra_val->o.via.str.size + 1);
            if (log_record->severity_text) {
                strncpy(log_record->severity_text, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
                severity_text_set = FLB_TRUE;
            }
        }
        flb_ra_key_value_destroy(ra_val);
    }

    if (!severity_text_set && ctx->ra_severity_text_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_text_metadata, *event->metadata);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_STR) {
                log_record->severity_text = flb_calloc(1, ra_val->o.via.str.size + 1);
                if (log_record->severity_text) {
                    strncpy(log_record->severity_text, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
                    severity_text_set = FLB_TRUE;
                }
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    if (!severity_text_set && ctx->ra_severity_text_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_severity_text_message, *event->body);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_STR) {
                log_record->severity_text = flb_calloc(1, ra_val->o.via.str.size + 1);
                if (log_record->severity_text) {
                    strncpy(log_record->severity_text, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
                    severity_text_set = FLB_TRUE;
                }
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    if (!severity_text_set) {
        /* To prevent invalid free */
        log_record->severity_text = NULL;
    }

    /* Attributes */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_attr, *event->metadata);
    if (ra_val != NULL) {
        if (ra_val->o.type == MSGPACK_OBJECT_MAP) {
            attr_count = 0;
            attrs = msgpack_map_to_otlp_kvarray(&ra_val->o, &attr_count);
            if (attrs) {
                if (log_record->attributes != NULL) {
                    if (otlp_kvarray_append(&log_record->attributes,
                                            &log_record->n_attributes,
                                            attrs, attr_count) != 0) {
                        otlp_kvarray_destroy(attrs, attr_count);
                    }
                }
                else {
                    log_record->attributes = attrs;
                    log_record->n_attributes = attr_count;
                }
            }
        }
        flb_ra_key_value_destroy(ra_val);
    }
    else if (ctx->ra_attributes_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_attributes_metadata, *event->metadata);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_MAP) {
                attr_count = 0;
                attrs = msgpack_map_to_otlp_kvarray(&ra_val->o, &attr_count);
                if (attrs) {
                    if (log_record->attributes != NULL) {
                        if (otlp_kvarray_append(&log_record->attributes,
                                                &log_record->n_attributes,
                                                attrs, attr_count) != 0) {
                            otlp_kvarray_destroy(attrs, attr_count);
                        }
                    }
                    else {
                        log_record->attributes = attrs;
                        log_record->n_attributes = attr_count;
                    }
                }
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* TraceId */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_trace_id, *event->metadata);
    if (ra_val != NULL) {
        ret = pack_trace_id(ctx, log_record, ra_val);
        if (ret == 0) {
            trace_id_set = FLB_TRUE;
        }
        flb_ra_key_value_destroy(ra_val);
    }

    if (!trace_id_set && ctx->ra_trace_id_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_trace_id_metadata, *event->metadata);
        if (ra_val != NULL) {
            ret = pack_trace_id(ctx, log_record, ra_val);
            if (ret == 0) {
                trace_id_set = FLB_TRUE;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    if (!trace_id_set && ctx->ra_trace_id_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_trace_id_message, *event->body);
        if (ra_val != NULL) {
            ret = pack_trace_id(ctx, log_record, ra_val);
            if (ret == 0) {
                trace_id_set = FLB_TRUE;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* SpanId */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_span_id, *event->metadata);
    if (ra_val != NULL) {
        ret = pack_span_id(ctx, log_record, ra_val);
        if (ret == 0) {
            span_id_set = FLB_TRUE;
        }
        flb_ra_key_value_destroy(ra_val);
    }

    if (!span_id_set && ctx->ra_span_id_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_span_id_metadata, *event->metadata);
        if (ra_val != NULL) {
            ret = pack_span_id(ctx, log_record, ra_val);
            if (ret == 0) {
                span_id_set = FLB_TRUE;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    if (!span_id_set && ctx->ra_span_id_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_span_id_message, *event->body);
        if (ra_val != NULL) {
            ret = pack_span_id(ctx, log_record, ra_val);
            if (ret == 0) {
                span_id_set = FLB_TRUE;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* TraceFlags */
    ra_val = flb_ra_get_value_object(ctx->ra_trace_flags_metadata, *event->metadata);
    if (ra_val != NULL) {
        if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            log_record->flags = (uint32_t) ra_val->o.via.u64;
            trace_flags_set = FLB_TRUE;
        }
        flb_ra_key_value_destroy(ra_val);
    }

    if (!trace_flags_set) {
        ra_val = flb_ra_get_value_object(ctx->ra_trace_flags_metadata, *event->metadata);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                log_record->flags = (uint32_t) ra_val->o.via.u64;
                trace_flags_set = FLB_TRUE;
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    /* EventName */
    ra_val = flb_ra_get_value_object(ctx->ra_log_meta_otlp_event_name, *event->metadata);
    if (ra_val != NULL) {
        if (ra_val->o.type == MSGPACK_OBJECT_STR) {
            log_record->event_name = flb_calloc(1, ra_val->o.via.str.size + 1);
            if (log_record->event_name) {
                strncpy(log_record->event_name, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
                event_name_set = FLB_TRUE;
            }
        }
        flb_ra_key_value_destroy(ra_val);
    }

    if (!event_name_set && ctx->ra_event_name_metadata) {
        ra_val = flb_ra_get_value_object(ctx->ra_event_name_metadata, *event->metadata);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_STR) {
                log_record->event_name = flb_calloc(1, ra_val->o.via.str.size + 1);
                if (log_record->event_name) {
                    strncpy(log_record->event_name, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
                    event_name_set = FLB_TRUE;
                }
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    if (!event_name_set && ctx->ra_event_name_message) {
        ra_val = flb_ra_get_value_object(ctx->ra_event_name_message, *event->body);
        if (ra_val != NULL) {
            if (ra_val->o.type == MSGPACK_OBJECT_STR) {
                log_record->event_name = flb_calloc(1, ra_val->o.via.str.size + 1);
                if (log_record->event_name) {
                    strncpy(log_record->event_name, ra_val->o.via.str.ptr, ra_val->o.via.str.size);
                    event_name_set = FLB_TRUE;
                }
            }
            flb_ra_key_value_destroy(ra_val);
        }
    }

    if (!event_name_set) {
        /* To prevent invalid free */
        log_record->event_name = NULL;
    }

    return 0;
}

static void free_log_records(Opentelemetry__Proto__Logs__V1__LogRecord **logs, size_t log_count)
{
    size_t index;
    Opentelemetry__Proto__Logs__V1__LogRecord *log;

    if (logs == NULL){
        return;
    }

    for (index = 0 ; index < log_count ; index++) {
        log = logs[index];

        if (log->body != NULL) {
            otlp_any_value_destroy(log->body);
            log->body = NULL;
        }

        if (log->attributes != NULL) {
            otlp_kvarray_destroy(log->attributes, log->n_attributes);
            log->attributes = NULL;
        }
        if (log->severity_text != NULL && log->severity_text != protobuf_c_empty_string) {
            flb_free(log->severity_text);
        }
        if (log->event_name != NULL && log->event_name != protobuf_c_empty_string) {
            flb_free(log->event_name);
        }
        if (log->span_id.data != NULL) {
            flb_free(log->span_id.data);
        }
        if (log->trace_id.data != NULL) {
            flb_free(log->trace_id.data);
        }

        flb_free(log);
    }
}

static void free_resource_logs(Opentelemetry__Proto__Logs__V1__ResourceLogs **resource_logs, size_t resource_count)
{
    int i;
    int scope_id;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log;

    if (resource_logs == NULL) {
        return;
    }

    for (i = 0 ; i < resource_count ; i++) {
        resource_log = resource_logs[i];

        if (resource_log->schema_url != NULL && resource_log->schema_url != protobuf_c_empty_string) {
            flb_sds_destroy(resource_log->schema_url);
        }

        if (resource_log->resource->attributes != NULL) {
            otlp_kvarray_destroy(resource_log->resource->attributes, resource_log->resource->n_attributes);
        }
        flb_free(resource_log->resource);

        /* iterate scoipe logs */
        if (resource_log->n_scope_logs > 0) {
            for (scope_id = 0; scope_id < resource_log->n_scope_logs; scope_id++) {
                 scope_log = resource_log->scope_logs[scope_id];

                if (scope_log->scope) {
                    if (scope_log->scope->name != NULL && scope_log->scope->name != protobuf_c_empty_string) {
                        flb_sds_destroy(scope_log->scope->name);
                    }

                    if (scope_log->scope->version != NULL && scope_log->scope->version != protobuf_c_empty_string) {
                        flb_sds_destroy(scope_log->scope->version);
                    }

                    if (scope_log->scope->attributes != NULL) {
                        otlp_kvarray_destroy(scope_log->scope->attributes, scope_log->scope->n_attributes);
                    }

                    flb_free(scope_log->scope);
                }

                if (scope_log->log_records != NULL) {
                    free_log_records(scope_log->log_records, scope_log->n_log_records);
                }

                flb_free(scope_log->log_records);
                flb_free(scope_log);
            }
            flb_free(resource_log->scope_logs);
        }

        flb_free(resource_log);
    }

    flb_free(resource_logs);
}

static int logs_flush_to_otel(struct opentelemetry_context *ctx, struct flb_event_chunk *event_chunk,
                              Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *export_logs)
{
    int ret;
    void *body;
    unsigned len;

    len = opentelemetry__proto__collector__logs__v1__export_logs_service_request__get_packed_size(export_logs);
    if (len == 0) {
        return FLB_ERROR;
    }

    body = flb_calloc(len, sizeof(char));
    if (!body) {
        flb_errno();
        return FLB_ERROR;
    }

    opentelemetry__proto__collector__logs__v1__export_logs_service_request__pack(export_logs, body);

    /* send post request to opentelemetry with content type application/x-protobuf */
    ret = opentelemetry_post(ctx, body, len,
                             event_chunk->tag,
                             flb_sds_len(event_chunk->tag),
                             ctx->logs_uri_sanitized,
                             ctx->grpc_logs_uri);
    flb_free(body);

    return ret;
}

static int set_resource_attributes(struct flb_record_accessor *ra,
                                   msgpack_object *map,
                                   Opentelemetry__Proto__Resource__V1__Resource *resource)
{
    struct flb_ra_value *ra_val;

    ra_val = flb_ra_get_value_object(ra, *map);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_MAP) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    resource->attributes = msgpack_map_to_otlp_kvarray(&ra_val->o,
                                                       &resource->n_attributes);
    flb_ra_key_value_destroy(ra_val);

    if (!resource->attributes) {
        return -1;
    }

    return 0;
}

static int set_resource_schema_url(struct flb_record_accessor *ra,
                                   msgpack_object *map,
                                   Opentelemetry__Proto__Logs__V1__ResourceLogs *resource)
{

    struct flb_ra_value *ra_val;

    ra_val = flb_ra_get_value_object(ra, *map);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_STR) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    resource->schema_url = flb_sds_create_len(ra_val->o.via.str.ptr,
                                              ra_val->o.via.str.size);
    flb_ra_key_value_destroy(ra_val);

    if (!resource->schema_url) {
        return -1;
    }

    return 0;
}

static int set_scope_schema_url(struct flb_record_accessor *ra,
                                msgpack_object *map,
                                Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log)
{

    struct flb_ra_value *ra_val;

    ra_val = flb_ra_get_value_object(ra, *map);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_STR) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    scope_log->schema_url = flb_sds_create_len(ra_val->o.via.str.ptr,
                                               ra_val->o.via.str.size);
    flb_ra_key_value_destroy(ra_val);

    if (!scope_log->schema_url) {
        return -1;
    }

    return 0;
}

static int set_scope_name(struct flb_record_accessor *ra,
                         msgpack_object *map,
                         Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    struct flb_ra_value *ra_val;

    ra_val = flb_ra_get_value_object(ra, *map);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_STR) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    scope->name = flb_sds_create_len(ra_val->o.via.str.ptr, ra_val->o.via.str.size);
    flb_ra_key_value_destroy(ra_val);
    if (!scope->name) {
        return -1;
    }

    return 0;
}

static int set_scope_version(struct flb_record_accessor *ra,
                             msgpack_object *map,
                             Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    struct flb_ra_value *ra_val;

    ra_val = flb_ra_get_value_object(ra, *map);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_STR) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    scope->version = flb_sds_create_len(ra_val->o.via.str.ptr, ra_val->o.via.str.size);
    flb_ra_key_value_destroy(ra_val);
    if (!scope->version) {
        return -1;
    }

    return 0;
}

static int set_scope_attributes(struct flb_record_accessor *ra,
                               msgpack_object *map,
                               Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    struct flb_ra_value *ra_val;

    ra_val = flb_ra_get_value_object(ra, *map);
    if (ra_val == NULL) {
        return -1;
    }

    if (ra_val->o.type != MSGPACK_OBJECT_MAP) {
        flb_ra_key_value_destroy(ra_val);
        return -1;
    }

    scope->attributes = msgpack_map_to_otlp_kvarray(&ra_val->o,
                                                   &scope->n_attributes);
    flb_ra_key_value_destroy(ra_val);

    if (!scope->attributes) {
        return -1;
    }

    return 0;
}

int otel_process_logs(struct flb_event_chunk *event_chunk,
                      struct flb_output_flush *out_flush,
                      struct flb_input_instance *ins, void *out_context,
                      struct flb_config *config)
{
    int ret;
    int record_type;
    int log_record_count;
    int max_scopes_limit;
    int max_resources;
    int native_otel = FLB_FALSE;
    size_t resource_logs_capacity;
    size_t i;
    size_t new_capacity;
    size_t resource_index = 0;
    size_t scope_capacity = 0;
    size_t new_scope_capacity = 0;
    int64_t resource_id = -1;
    int64_t scope_id = -1;
    int64_t tmp_resource_id = -1;
    int64_t tmp_scope_id = -1;
    struct flb_log_event_decoder *decoder;
    struct flb_log_event event;
    struct opentelemetry_context *ctx;
    struct flb_record_accessor *ra_match;
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest export_logs;
    Opentelemetry__Proto__Logs__V1__ResourceLogs **resource_logs = NULL;
    Opentelemetry__Proto__Logs__V1__ResourceLogs **tmp_resource_logs = NULL;
    Opentelemetry__Proto__Logs__V1__ResourceLogs *resource_log = NULL;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **scope_logs = NULL;
    Opentelemetry__Proto__Logs__V1__ScopeLogs **tmp_scope_logs = NULL;
    Opentelemetry__Proto__Logs__V1__ScopeLogs *scope_log = NULL;
    Opentelemetry__Proto__Logs__V1__LogRecord **log_records = NULL;
    Opentelemetry__Proto__Logs__V1__LogRecord  *log_record = NULL;
    size_t *resource_scope_capacities = NULL;
    size_t *tmp_scope_capacities = NULL;

    ctx = (struct opentelemetry_context *) out_context;

    decoder = flb_log_event_decoder_create((char *) event_chunk->data, event_chunk->size);
    if (decoder == NULL) {
        flb_plg_error(ctx->ins, "could not initialize record decoder");
        return -1;
    }

    flb_log_event_decoder_read_groups(decoder, FLB_TRUE);

    log_record_count = 0;
    opentelemetry__proto__collector__logs__v1__export_logs_service_request__init(&export_logs);

    /* local limits */
    max_resources = ctx->max_resources; /* maximum number of resources */
    max_scopes_limit = ctx->max_scopes;    /* maximum number of scopes per resource */

    if (max_resources > 0) {
        resource_logs_capacity = max_resources;
    }
    else {
        resource_logs_capacity = RESOURCE_LOGS_INITIAL_CAPACITY; /* grow dynamically when unlimited */
    }

    /* allocate storage for the configured number of resource logs */
    resource_logs = flb_calloc(resource_logs_capacity,
                               sizeof(Opentelemetry__Proto__Logs__V1__ResourceLogs *));
    if (!resource_logs) {
        flb_errno();
        flb_log_event_decoder_destroy(decoder);
        return -1;
    }
    resource_scope_capacities = flb_calloc(resource_logs_capacity, sizeof(size_t));
    if (!resource_scope_capacities) {
        flb_errno();
        flb_free(resource_logs);
        flb_log_event_decoder_destroy(decoder);
        return -1;
    }
    export_logs.resource_logs = resource_logs;
    export_logs.n_resource_logs = 0;

    ret = FLB_OK;
    while (flb_log_event_decoder_next(decoder, &event) == FLB_EVENT_DECODER_SUCCESS) {
        /* Check if the record is special (group) or a normal one */
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "record has invalid event type");
            continue;
        }

        /*
         * Group start: handle resource an scope
         * -------------------------------------
         */
        if (record_type == FLB_LOG_EVENT_GROUP_START) {
            /* Look for OTLP info */
            tmp_resource_id = -1;
            tmp_scope_id = -1;

            ret = get_otlp_group_metadata(ctx, &event, &tmp_resource_id, &tmp_scope_id);
            if (ret == -1) {
                /* skip unknown group info */
                continue;
            }

            /* flag this as a native otel schema */
            native_otel = FLB_TRUE;


            /* if we have a new resource_id, start a new resource context */
            if (resource_id != tmp_resource_id) {
                if (max_resources > 0) {
                    if (export_logs.n_resource_logs >= max_resources) {
                        /* respect the configured resource batching limit */
                        flb_plg_error(ctx->ins, "max resources limit reached");
                        ret = FLB_ERROR;
                        break;
                    }
                }
                else if (export_logs.n_resource_logs >= resource_logs_capacity) {
                    new_capacity = resource_logs_capacity * 2;
                    if (new_capacity <= resource_logs_capacity) {
                        flb_plg_error(ctx->ins, "resource logs capacity overflow");
                        ret = FLB_ERROR;
                        break;
                    }

                    if (new_capacity < RESOURCE_LOGS_INITIAL_CAPACITY) {
                        new_capacity = RESOURCE_LOGS_INITIAL_CAPACITY;
                    }

                    tmp_resource_logs = flb_realloc(resource_logs,
                                                     new_capacity * sizeof(Opentelemetry__Proto__Logs__V1__ResourceLogs *));
                    if (!tmp_resource_logs) {
                        flb_errno();
                        ret = FLB_RETRY;
                        break;
                    }
                    resource_logs = tmp_resource_logs;
                    export_logs.resource_logs = resource_logs;

                    tmp_scope_capacities = flb_realloc(resource_scope_capacities,
                                                       new_capacity * sizeof(size_t));
                    if (!tmp_scope_capacities) {
                        flb_errno();
                        ret = FLB_RETRY;
                        break;
                    }

                    resource_scope_capacities = tmp_scope_capacities;

                    for (i = resource_logs_capacity; i < new_capacity; i++) {
                        resource_logs[i] = NULL;
                        resource_scope_capacities[i] = 0;
                    }

                    resource_logs_capacity = new_capacity;
                }

start_resource:
                /*
                * On every group start, check if we are following the previous resource_id or not, so we can pack scopes
                * under the right resource.
                */
                resource_log = flb_calloc(1, sizeof(Opentelemetry__Proto__Logs__V1__ResourceLogs));
                if (!resource_log) {
                    flb_errno();
                    ret = FLB_RETRY;
                    break;
                }
                opentelemetry__proto__logs__v1__resource_logs__init(resource_log);

                /* add the resource log */
                resource_logs[export_logs.n_resource_logs] = resource_log;
                export_logs.n_resource_logs++;

                resource_index = export_logs.n_resource_logs - 1;

                resource_log->resource = flb_calloc(1, sizeof(Opentelemetry__Proto__Resource__V1__Resource));
                if (!resource_log->resource) {
                    flb_errno();
                    flb_free(resource_log);
                    ret = FLB_RETRY;
                    break;
                }
                opentelemetry__proto__resource__v1__resource__init(resource_log->resource);

                /* group body: $resource['attributes'] */
                set_resource_attributes(ctx->ra_resource_attr, event.body, resource_log->resource);

                /* group body: $schema_url */
                set_resource_schema_url(ctx->ra_resource_schema_url, event.body, resource_log);

                /* prepare the scopes */
                if (!resource_log->scope_logs) {
                    if (max_scopes_limit > 0) {
                        scope_capacity = (size_t) max_scopes_limit;
                    }
                    else {
                        scope_capacity = resource_scope_capacities[resource_index];
                        if (scope_capacity == 0) {
                            scope_capacity = SCOPE_LOGS_INITIAL_CAPACITY;
                        }
                    }

                    scope_logs = flb_calloc(scope_capacity, sizeof(Opentelemetry__Proto__Logs__V1__ScopeLogs *));
                    if (!scope_logs) {
                        flb_errno();
                        ret = FLB_RETRY;
                        break;
                    }

                    resource_log->scope_logs = scope_logs;
                    resource_log->n_scope_logs = 0;
                    resource_scope_capacities[resource_index] = scope_capacity;
                }

                /* update the current resource_id and reset scope_id */
                resource_id = tmp_resource_id;
                scope_id = -1;
            }

            if (scope_id != tmp_scope_id) {
                resource_index = export_logs.n_resource_logs - 1;

                /* check limits */
                if (max_scopes_limit > 0) {
                    if (resource_log->n_scope_logs >= max_scopes_limit) {
                        flb_plg_error(ctx->ins, "max scopes limit reached");
                        ret = FLB_ERROR;
                        break;
                    }
                }
                else {
                    if (resource_log->n_scope_logs >= resource_scope_capacities[resource_index]) {
                        new_scope_capacity = resource_scope_capacities[resource_index] * 2;

                        if (new_scope_capacity <= resource_scope_capacities[resource_index]) {
                            flb_plg_error(ctx->ins, "scope logs capacity overflow");
                            ret = FLB_ERROR;
                            break;
                        }

                        if (new_scope_capacity < SCOPE_LOGS_INITIAL_CAPACITY) {
                            new_scope_capacity = SCOPE_LOGS_INITIAL_CAPACITY;
                        }

                        tmp_scope_logs = flb_realloc(resource_log->scope_logs,
                                                     new_scope_capacity * sizeof(Opentelemetry__Proto__Logs__V1__ScopeLogs *));
                        if (!tmp_scope_logs) {
                            flb_errno();
                            ret = FLB_RETRY;
                            break;
                        }

                        for (i = resource_scope_capacities[resource_index];
                             i < new_scope_capacity; i++) {
                            tmp_scope_logs[i] = NULL;
                        }

                        resource_log->scope_logs = tmp_scope_logs;
                        resource_scope_capacities[resource_index] = new_scope_capacity;
                    }
                }

                /* process the scope */
                scope_log = flb_calloc(1, sizeof(Opentelemetry__Proto__Logs__V1__ScopeLogs));
                if (!scope_log) {
                    flb_errno();
                    ret = FLB_RETRY;
                    break;
                }
                opentelemetry__proto__logs__v1__scope_logs__init(scope_log);

                scope_log->scope = flb_calloc(1, sizeof(Opentelemetry__Proto__Common__V1__InstrumentationScope));
                if (!scope_log->scope) {
                    flb_errno();
                    flb_free(scope_log);
                    ret = FLB_RETRY;
                    break;
                }
                opentelemetry__proto__common__v1__instrumentation_scope__init(scope_log->scope);
                scope_id = tmp_scope_id;

                log_records = flb_calloc(ctx->batch_size, sizeof(Opentelemetry__Proto__Logs__V1__LogRecord *));
                if (!log_records) {
                    flb_errno();
                    flb_free(scope_log->scope);
                    flb_free(scope_log);
                    ret = FLB_RETRY;
                    break;
                }
                log_record_count = 0;

                scope_log->log_records = log_records;
                resource_log->scope_logs[resource_log->n_scope_logs] = scope_log;
                resource_log->n_scope_logs++;

                /* group body: $scope['name'] */
                set_scope_name(ctx->ra_scope_name, event.body, scope_log->scope);

                /* group body: $scope['version'] */
                set_scope_version(ctx->ra_scope_version, event.body, scope_log->scope);

                /* group body: $scope['attributes'] */
                set_scope_attributes(ctx->ra_scope_attr, event.body, scope_log->scope);

                /* group body: $scope['schema_url'] */
                set_scope_schema_url(ctx->ra_scope_schema_url, event.body, scope_log);
            }

            ret = FLB_OK;

            /*
             * if we started a new group through a valid OTLP schema, just continue since the active record
             * is a group start. If native_otel is off it means the packaging was done for a record which is
             * not OTLP schema compatible so it needs to be processed (do not skip it).
             */
            if (native_otel) {
                continue;
            }
        }
        else if (record_type == FLB_LOG_EVENT_GROUP_END) {
            /* do nothing */
            ret = FLB_OK;
            resource_id = -1;
            scope_id = -1;
            native_otel = FLB_FALSE;

            continue;
        }

        /* if we have a real OTLP context package using log_records */
        if (resource_id >= 0 && scope_id >= 0) {

        }
        else {
            /*
             * standalone packaging: the record is not part of an original OTLP structure, so there is no group
             * information. We create a temporary resource for the incoming records unless a group is defined.
             */
            tmp_resource_id = 0;
            tmp_scope_id = 0;
            goto start_resource;
        }

        ra_match = NULL;
        log_record = flb_calloc(1, sizeof(Opentelemetry__Proto__Logs__V1__LogRecord));
        if (!log_record) {
            flb_errno();
            ret = FLB_RETRY;
            break;
        }

        log_records[log_record_count] = log_record;
        opentelemetry__proto__logs__v1__log_record__init(log_record);

        /*
         * Set the record body by using the logic defined in the configuration by
         * the 'logs_body_key' properties.
         *
         * Note that the reference set in `out_body_parent_key` is the parent/root key that holds the content
         * that was discovered. We get that reference so we can easily filter it out when composing
         * the final list of attributes.
         */
        ret = log_record_set_body(ctx, log_record, &event, &ra_match);
        if (ret == -1) {
            /* the only possible fail path is a problem with a memory allocation, let's suggest a FLB_RETRY */
            ret = FLB_RETRY;
            flb_free(log_record);
            log_records[log_record_count] = NULL;
            break;
        }

        /* set attributes from metadata and remaining fields from the main record */
        ret = log_record_set_attributes(ctx, log_record, &event, ra_match);
        if (ret == -1) {
            /* as before, it can only fail on a memory allocation */
            ret = FLB_RETRY;
            if (log_record->body) {
                otlp_any_value_destroy(log_record->body);
            }
            flb_free(log_record);
            log_records[log_record_count] = NULL;
            break;
        }

        append_v1_logs_metadata_and_fields(ctx, &event, log_record);

        ret = FLB_OK;
        log_record_count++;
        scope_log->n_log_records = log_record_count;

        if (log_record_count >= ctx->batch_size) {
            ret = logs_flush_to_otel(ctx, event_chunk, &export_logs);
            free_log_records(log_records, log_record_count);
            log_record_count = 0;
            scope_log->n_log_records = 0;
        }
    }

    flb_log_event_decoder_destroy(decoder);

    if (log_record_count > 0 && ret == FLB_OK) {
        ret = logs_flush_to_otel(ctx, event_chunk, &export_logs);
    }

    /* release all protobuf resources */
    free_resource_logs(export_logs.resource_logs, export_logs.n_resource_logs);
    flb_free(resource_scope_capacities);

    return ret;
}
