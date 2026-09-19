/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 The CTraces Authors
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

#include "ctr_protobuf.h"
#include <ctraces/ctraces.h>
#include <ctraces/ctr_variant_utils.h>
#include <cfl/cfl_array.h>
#include <fluent-otel-proto/fluent-otel.h>

static int convert_any_value(struct opentelemetry_decode_value *ctr_val,
                             opentelemetry_decode_value_type value_type, char *key,
                             Opentelemetry__Proto__Common__V1__AnyValue *val, size_t depth);

static int convert_string_value(struct opentelemetry_decode_value *ctr_val,
                                opentelemetry_decode_value_type value_type,
                                char *key, char *val)
{
    int result;

    /* cfl_array_append_string and cfl_variant_create_from_string call
     * strlen() unguarded, so a NULL value would crash here.
     */
    if (val == NULL) {
        return -1;
    }

    result = -2;

    switch (value_type) {

        case CTR_OPENTELEMETRY_TYPE_ATTRIBUTE:
            result = ctr_attributes_set_string(ctr_val->ctr_attr, key, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_ARRAY:
            result = cfl_array_append_string(ctr_val->cfl_arr, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_KVLIST:
            result = cfl_kvlist_insert_string(ctr_val->cfl_kvlist, key, val);
            break;

    }

    if (result == -2) {
        printf("convert_string_value: unknown value type");
    }

    return result;
}

static int convert_bool_value(struct opentelemetry_decode_value *ctr_val,
                              opentelemetry_decode_value_type value_type,
                              char *key, protobuf_c_boolean val)
{
    int result;

    result = -2;

    switch (value_type) {

        case CTR_OPENTELEMETRY_TYPE_ATTRIBUTE:
            result = ctr_attributes_set_bool(ctr_val->ctr_attr, key, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_ARRAY:
            result = cfl_array_append_bool(ctr_val->cfl_arr, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_KVLIST:
            result = cfl_kvlist_insert_bool(ctr_val->cfl_kvlist, key, val);
            break;

    }

    if (result == -2) {
        printf("convert_bool_value: unknown value type");
    }

    return result;
}

static int convert_int_value(struct opentelemetry_decode_value *ctr_val,
                             opentelemetry_decode_value_type value_type,
                             char *key, int64_t val)
{
    int result;

    result = -2;

    switch (value_type) {

        case CTR_OPENTELEMETRY_TYPE_ATTRIBUTE:
            result = ctr_attributes_set_int64(ctr_val->ctr_attr, key, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_ARRAY:
            result = cfl_array_append_int64(ctr_val->cfl_arr, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_KVLIST:
            result = cfl_kvlist_insert_int64(ctr_val->cfl_kvlist, key, val);
            break;

    }

    if (result == -2) {
        printf("convert_int_value: unknown value type");
    }

    return result;
}

static int convert_double_value(struct opentelemetry_decode_value *ctr_val,
                                opentelemetry_decode_value_type value_type,
                                char *key, double val)
{
    int result;

    result = -2;

    switch (value_type) {

        case CTR_OPENTELEMETRY_TYPE_ATTRIBUTE:
            result = ctr_attributes_set_double(ctr_val->ctr_attr, key, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_ARRAY:
            result = cfl_array_append_double(ctr_val->cfl_arr, val);
            break;

        case CTR_OPENTELEMETRY_TYPE_KVLIST:
            result = cfl_kvlist_insert_double(ctr_val->cfl_kvlist, key, val);
            break;

    }

    if (result == -2) {
        printf("convert_double_value: unknown value type");
    }

    return result;
}

static int convert_array_value(struct opentelemetry_decode_value *ctr_val,
                               opentelemetry_decode_value_type value_type,
                               char *key, Opentelemetry__Proto__Common__V1__ArrayValue *otel_arr,
                               size_t depth)
{
    int array_index;
    int result;
    struct opentelemetry_decode_value *ctr_arr_val;
    Opentelemetry__Proto__Common__V1__AnyValue *val;

    if (depth >= CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH || otel_arr == NULL) {
        return -1;
    }
    if (otel_arr->n_values > 0 && otel_arr->values == NULL) {
        return -1;
    }

    ctr_arr_val = malloc(sizeof(struct opentelemetry_decode_value));
    if (!ctr_arr_val) {
        ctr_errno();
        return -1;
    }
    ctr_arr_val->cfl_arr = cfl_array_create(otel_arr->n_values);
    if (!ctr_arr_val->cfl_arr) {
        free(ctr_arr_val);
        return -1;
    }

    result = 0;

    for (array_index = 0;
         array_index < otel_arr->n_values && result == 0;
         array_index++) {
        val = otel_arr->values[array_index];
        if (val == NULL) {
            /* skip malformed entry rather than failing the whole array */
            continue;
        }
        result = convert_any_value(ctr_arr_val, CTR_OPENTELEMETRY_TYPE_ARRAY, NULL, val, depth + 1);
    }

    if (result < 0) {
        cfl_array_destroy(ctr_arr_val->cfl_arr);
        free(ctr_arr_val);
        return result;
    }

    result = -2;

    switch (value_type) {

        case CTR_OPENTELEMETRY_TYPE_ATTRIBUTE:
            result = ctr_attributes_set_array(ctr_val->ctr_attr, key, ctr_arr_val->cfl_arr);
            break;

        case CTR_OPENTELEMETRY_TYPE_ARRAY:
            result = cfl_array_append_array(ctr_val->cfl_arr, ctr_arr_val->cfl_arr);
            break;

        case CTR_OPENTELEMETRY_TYPE_KVLIST:
            result = cfl_kvlist_insert_array(ctr_val->cfl_kvlist, key, ctr_arr_val->cfl_arr);
            break;

    }

    free(ctr_arr_val);
    if (result == -2) {
        fprintf(stderr, "convert_array_value: unknown value type\n");
    }

    return result;
}

static int convert_kvlist_value(struct opentelemetry_decode_value *ctr_val,
                                opentelemetry_decode_value_type value_type,
                                char *key, Opentelemetry__Proto__Common__V1__KeyValueList *otel_kvlist,
                                size_t depth)
{
    int kvlist_index;
    int result;
    struct opentelemetry_decode_value *ctr_kvlist_val;
    Opentelemetry__Proto__Common__V1__KeyValue *kv;

    if (depth >= CFL_VARIANT_UTILS_MAXIMUM_NESTING_DEPTH || otel_kvlist == NULL) {
        return -1;
    }
    if (otel_kvlist->n_values > 0 && otel_kvlist->values == NULL) {
        return -1;
    }

    ctr_kvlist_val = malloc(sizeof(struct opentelemetry_decode_value));
    if (!ctr_kvlist_val) {
        ctr_errno();
        return -1;
    }
    ctr_kvlist_val->cfl_kvlist = cfl_kvlist_create();
    if (!ctr_kvlist_val->cfl_kvlist) {
        free(ctr_kvlist_val);
        return -1;
    }

    result = 0;
    for (kvlist_index = 0;
         kvlist_index < otel_kvlist->n_values && result ==0;
         kvlist_index++) {

        kv = otel_kvlist->values[kvlist_index];
        /* skip entries that would crash strlen() inside the cfl_kvlist
         * inserters (which don't NULL-check the key for non-string types).
         */
        if (kv == NULL || kv->key == NULL || kv->value == NULL) {
            continue;
        }
        result = convert_any_value(ctr_kvlist_val, CTR_OPENTELEMETRY_TYPE_KVLIST,
                                   kv->key, kv->value, depth + 1);
    }

    if (result < 0){
        cfl_kvlist_destroy(ctr_kvlist_val->cfl_kvlist);
        free(ctr_kvlist_val);
        return result;
    }

    result = -2;

    switch (value_type) {

        case CTR_OPENTELEMETRY_TYPE_ATTRIBUTE:
            result = ctr_attributes_set_kvlist(ctr_val->ctr_attr, key, ctr_kvlist_val->cfl_kvlist);
            break;

        case CTR_OPENTELEMETRY_TYPE_ARRAY:
            result = cfl_array_append_kvlist(ctr_val->cfl_arr, ctr_kvlist_val->cfl_kvlist);
            break;

        case CTR_OPENTELEMETRY_TYPE_KVLIST:
            result = cfl_kvlist_insert_kvlist(ctr_val->cfl_kvlist, key, ctr_kvlist_val->cfl_kvlist);
            break;

    }

    free(ctr_kvlist_val);

    if (result == -2) {
        printf("convert_kvlist_value: unknown value type");
    }

    return result;
}

static int convert_bytes_value(struct opentelemetry_decode_value *ctr_val,
                               opentelemetry_decode_value_type value_type,
                               char *key, void *buf, size_t len)
{
    int result;

    result = -2;

    switch (value_type) {
        case CTR_OPENTELEMETRY_TYPE_ATTRIBUTE:
            result = cfl_kvlist_insert_bytes(ctr_val->ctr_attr->kv, key,
                                             buf, len, CFL_FALSE);
            break;

        case CTR_OPENTELEMETRY_TYPE_ARRAY:
            result = cfl_array_append_bytes(ctr_val->cfl_arr, buf, len, CFL_FALSE);
            break;

        case CTR_OPENTELEMETRY_TYPE_KVLIST:
            result = cfl_kvlist_insert_bytes(ctr_val->cfl_kvlist, key, buf, len, CFL_FALSE);
            break;
    }

    if (result == -2) {
        printf("convert_bytes_value: unknown value type");
    }

    return result;
}

static int convert_any_value(struct opentelemetry_decode_value *ctr_val,
                             opentelemetry_decode_value_type value_type, char *key,
                             Opentelemetry__Proto__Common__V1__AnyValue *val, size_t depth)
{
    int result;

    if (val == NULL) {
        return -1;
    }
    switch (val->value_case) {

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE:
            if (val->string_value == NULL) {
                result = -1;
            }
            else {
                result = convert_string_value(ctr_val, value_type, key, val->string_value);
            }
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE_STRINDEX:
            /* Profiling-only string dictionary reference: ignore in traces. */
            result = 0;
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE:
            result = convert_bool_value(ctr_val, value_type, key, val->bool_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE:
            result = convert_int_value(ctr_val, value_type, key, val->int_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE:
            result = convert_double_value(ctr_val, value_type, key, val->double_value);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE:
            result = convert_array_value(ctr_val, value_type, key, val->array_value, depth);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE:
            result = convert_kvlist_value(ctr_val, value_type, key, val->kvlist_value, depth);
            break;

        case OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE:
            if (val->bytes_value.len > 0 && val->bytes_value.data == NULL) {
                result = -1;
            }
            else {
                result = convert_bytes_value(ctr_val, value_type, key, val->bytes_value.data, val->bytes_value.len);
            }
            break;

        default:
            result = -1;
            break;
        }

    return result;
}

static struct ctrace_attributes *convert_otel_attrs(size_t n_attributes,
                                                    Opentelemetry__Proto__Common__V1__KeyValue **otel_attr)
{
    int index_kv;
    int result;
    char *key;
    struct opentelemetry_decode_value *ctr_decoded_attributes;
    struct ctrace_attributes *attr;

    Opentelemetry__Proto__Common__V1__KeyValue *kv;
    Opentelemetry__Proto__Common__V1__AnyValue *val;

    ctr_decoded_attributes = malloc(sizeof(struct opentelemetry_decode_value));
    if (!ctr_decoded_attributes) {
        ctr_errno();
        return NULL;
    }

    ctr_decoded_attributes->ctr_attr = ctr_attributes_create();
    if (!ctr_decoded_attributes->ctr_attr) {
        free(ctr_decoded_attributes);
        return NULL;
    }

    result = 0;

    if (n_attributes > 0 && otel_attr == NULL) {
        ctr_attributes_destroy(ctr_decoded_attributes->ctr_attr);
        free(ctr_decoded_attributes);
        return NULL;
    }

    for (index_kv = 0; index_kv < n_attributes && result == 0; index_kv++) {
        kv = otel_attr[index_kv];
        /* Skip malformed entries that would otherwise crash strlen() inside
         * the cfl_kvlist inserters (none of the non-string variants checks
         * the key for NULL).
         */
        if (kv == NULL || kv->key == NULL || kv->value == NULL) {
            continue;
        }

        key = kv->key;
        val = kv->value;

        result = convert_any_value(ctr_decoded_attributes,
                                       CTR_OPENTELEMETRY_TYPE_ATTRIBUTE,
                                       key, val, 1);
    }

    if (result < 0) {
        ctr_attributes_destroy(ctr_decoded_attributes->ctr_attr);
        free(ctr_decoded_attributes);
        return NULL;
    }

    attr = ctr_decoded_attributes->ctr_attr;
    free(ctr_decoded_attributes);
    return attr;
}

static int span_set_attributes(struct ctrace_span *span,
                               size_t n_attributes,
                               Opentelemetry__Proto__Common__V1__KeyValue **attributes)
{
    struct ctrace_attributes *ctr_attributes;

    ctr_attributes = convert_otel_attrs(n_attributes, attributes);
    if (ctr_attributes == NULL) {
        return -1;
    }

    if (span->attr) {
        ctr_attributes_destroy(span->attr);
    }
    span->attr = ctr_attributes;
    return 0;
}

static int span_set_events(struct ctrace_span *span,
                           size_t n_events,
                           Opentelemetry__Proto__Trace__V1__Span__Event **events)
{
    int index_event;
    struct ctrace_span_event *ctr_event;
    struct ctrace_attributes *ctr_attributes;
    Opentelemetry__Proto__Trace__V1__Span__Event *event;

    cfl_list_init(&span->events);

    if (n_events > 0 && events == NULL) {
        return -1;
    }

    for (index_event = 0; index_event < n_events; index_event++) {
        event = events[index_event];
        if (event == NULL || event->name == NULL) {
            /* skip malformed event rather than failing the whole span */
            continue;
        }

        ctr_event = ctr_span_event_add_ts(span, event->name, event->time_unix_nano);
        if (ctr_event == NULL) {
            return -1;
        }

        if (event->n_attributes > 0 && event->attributes != NULL) {
            ctr_attributes = convert_otel_attrs(event->n_attributes, event->attributes);
            if (ctr_attributes == NULL) {
                return -1;
            }
            else {
                ctr_span_event_set_attributes(ctr_event, ctr_attributes);
            }
        }
        ctr_span_event_set_dropped_attributes_count(ctr_event, event->dropped_attributes_count);
    }

    return 0;
}

static int resource_set_data(struct ctrace_resource *resource,
                             Opentelemetry__Proto__Resource__V1__Resource *otel_resource)
{
    struct ctrace_attributes *attributes;

    attributes = convert_otel_attrs(otel_resource->n_attributes, otel_resource->attributes);

    if (attributes == NULL) {
        return -1;
    }

    ctr_resource_set_attributes(resource, attributes);
    ctr_resource_set_dropped_attr_count(resource, otel_resource->dropped_attributes_count);

    return 0;
}

static int ctr_scope_span_set_scope(struct ctrace_scope_span *scope_span,
                                    Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    struct ctrace_attributes *ctr_attributes;
    struct ctrace_instrumentation_scope *ins_scope;

    ctr_attributes = convert_otel_attrs(scope->n_attributes, scope->attributes);
    if (ctr_attributes == NULL) {
        return -1;
    }

    ins_scope = ctr_instrumentation_scope_create(scope->name, scope->version,
                                                 scope->dropped_attributes_count,
                                                 ctr_attributes);
    if (!ins_scope) {
        ctr_attributes_destroy(ctr_attributes);
        return -1;
    }

    ctr_scope_span_set_instrumentation_scope(scope_span, ins_scope);

    return 0;
}

static int ctr_span_set_links(struct ctrace_span *ctr_span, size_t n_links,
                              Opentelemetry__Proto__Trace__V1__Span__Link **links)
{
    int index_link;
    struct ctrace_link *ctr_link;
    struct ctrace_attributes *ctr_attributes;
    Opentelemetry__Proto__Trace__V1__Span__Link *link;

    if (n_links > 0 && links == NULL) {
        return -1;
    }

    for (index_link = 0; index_link < n_links; index_link++) {
        link = links[index_link];
        if (link == NULL) {
            /* skip malformed link rather than dropping the rest */
            continue;
        }

        ctr_link = ctr_link_create(ctr_span,
                                   link->trace_id.data, link->trace_id.len,
                                   link->span_id.data, link->span_id.len);

        if (ctr_link == NULL) {
            return -1;
        }

        ctr_attributes = convert_otel_attrs(link->n_attributes, link->attributes);

        if (ctr_attributes == NULL) {
            return -1;
        }

        ctr_link->attr = ctr_attributes;
        if (link->trace_state != NULL && link->trace_state[0] != '\0') {
            if (ctr_link_set_trace_state(ctr_link, link->trace_state) != 0) {
                return -1;
            }
        }
        ctr_link_set_dropped_attr_count(ctr_link, link->dropped_attributes_count);
        ctr_link_set_flags(ctr_link, link->flags);
    }

    return 0;
}

static int decode_opentelemetry_error(
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *request,
    struct ctrace *ctr, int result)
{
    opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(
        request, NULL);
    ctr_destroy(ctr);

    return result;
}

int ctr_decode_opentelemetry_create(struct ctrace **out_ctr,
                                    char *in_buf,
                                    size_t in_size, size_t *offset)
{
    size_t resource_span_index;
    size_t scope_span_index;
    size_t span_index;
    struct ctrace *ctr;
    struct ctrace_span *span;
    struct ctrace_resource *resource;
    struct ctrace_resource_span *resource_span;
    struct ctrace_scope_span *scope_span;

    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *service_request;
    Opentelemetry__Proto__Trace__V1__ResourceSpans *otel_resource_span;
    Opentelemetry__Proto__Trace__V1__ScopeSpans *otel_scope_span;
    Opentelemetry__Proto__Trace__V1__Span *otel_span;

    if (out_ctr == NULL || in_buf == NULL || offset == NULL) {
        return CTR_DECODE_OPENTELEMETRY_INVALID_ARGUMENT;
    }

    *out_ctr = NULL;

    if (*offset > in_size || (*offset == in_size && in_size != 0)) {
        return CTR_DECODE_OPENTELEMETRY_INSUFFICIENT_DATA;
    }

    if (ctr_protobuf_validate(
            &opentelemetry__proto__collector__trace__v1__export_trace_service_request__descriptor,
            &in_buf[*offset], in_size - *offset) != 0) {
        return CTR_DECODE_OPENTELEMETRY_CORRUPTED_DATA;
    }

    service_request = opentelemetry__proto__collector__trace__v1__export_trace_service_request__unpack(NULL,
                                                                                                      in_size - *offset,
                                                                                                      (unsigned char *) &in_buf[*offset]);
    if (service_request == NULL) {
        return CTR_DECODE_OPENTELEMETRY_CORRUPTED_DATA;
    }

    ctr = ctr_create(NULL);
    if (ctr == NULL) {
        opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
        return CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (service_request->n_resource_spans > 0 && service_request->resource_spans == NULL) {
        opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
        ctr_destroy(ctr);
        return CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD;
    }

    for (resource_span_index = 0; resource_span_index < service_request->n_resource_spans; resource_span_index++) {
        otel_resource_span = service_request->resource_spans[resource_span_index];
        if (otel_resource_span == NULL || otel_resource_span->resource == NULL) {
            opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
            ctr_destroy(ctr);
            return CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD;
        }

        /* resource span */
        resource_span = ctr_resource_span_create(ctr);
        if (resource_span == NULL) {
            return decode_opentelemetry_error(service_request, ctr,
                                               CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR);
        }
        ctr_resource_span_set_schema_url(resource_span, otel_resource_span->schema_url);

        /* resource */
        resource = ctr_resource_span_get_resource(resource_span);
        if (resource_set_data(resource, otel_resource_span->resource) != 0) {
            return decode_opentelemetry_error(service_request, ctr,
                                               CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR);
        }

        ctr_resource_set_dropped_attr_count(resource, otel_resource_span->resource->dropped_attributes_count);

        if (otel_resource_span->n_scope_spans > 0 && otel_resource_span->scope_spans == NULL) {
            opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
            ctr_destroy(ctr);
            return CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD;
        }

        for (scope_span_index = 0; scope_span_index < otel_resource_span->n_scope_spans; scope_span_index++) {
            otel_scope_span = otel_resource_span->scope_spans[scope_span_index];

            if (otel_scope_span == NULL) {
                opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
                ctr_destroy(ctr);

                return CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD;
            }

            scope_span = ctr_scope_span_create(resource_span);

            if (scope_span == NULL) {
                opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
                ctr_destroy(ctr);

                return CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            ctr_scope_span_set_schema_url(scope_span, otel_scope_span->schema_url);

            if (otel_scope_span->scope != NULL) {
                if (ctr_scope_span_set_scope(scope_span, otel_scope_span->scope) != 0) {
                    return decode_opentelemetry_error(
                        service_request, ctr, CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR);
                }
            }

            if (otel_scope_span->n_spans > 0 && otel_scope_span->spans == NULL) {
                opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
                ctr_destroy(ctr);
                return CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD;
            }

            for (span_index = 0; span_index < otel_scope_span->n_spans; span_index++) {
                otel_span = otel_scope_span->spans[span_index];

                if (otel_span == NULL || otel_span->name == NULL) {
                    opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
                    ctr_destroy(ctr);

                    return CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD;
                }

                span = ctr_span_create(ctr, scope_span, otel_span->name, NULL);

                if (span == NULL) {
                    opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);
                    ctr_destroy(ctr);

                    return CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }

                /* copy data from otel span to ctraces span representation */
                if ((otel_span->trace_id.len > 0 &&
                     ctr_span_set_trace_id(span, otel_span->trace_id.data,
                                           otel_span->trace_id.len) != 0) ||
                    (otel_span->span_id.len > 0 &&
                     ctr_span_set_span_id(span, otel_span->span_id.data,
                                          otel_span->span_id.len) != 0) ||
                    (otel_span->parent_span_id.len > 0 &&
                     ctr_span_set_parent_span_id(span, otel_span->parent_span_id.data,
                                                 otel_span->parent_span_id.len) != 0)) {
                    return decode_opentelemetry_error(
                        service_request, ctr, CTR_DECODE_OPENTELEMETRY_ALLOCATION_ERROR);
                }

                if (otel_span->trace_state && strlen(otel_span->trace_state) > 0) {
                    ctr_span_set_trace_state(span, otel_span->trace_state, strlen(otel_span->trace_state));
                }

                if (ctr_span_kind_set(span, otel_span->kind) != 0) {
                    return decode_opentelemetry_error(
                        service_request, ctr, CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD);
                }
                ctr_span_set_flags(span, otel_span->flags);
                ctr_span_start_ts(ctr, span, otel_span->start_time_unix_nano);
                ctr_span_end_ts(ctr, span, otel_span->end_time_unix_nano);

                if (otel_span->status) {
                    if (ctr_span_set_status(span, otel_span->status->code,
                                            otel_span->status->message) != 0) {
                        return decode_opentelemetry_error(
                            service_request, ctr, CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD);
                    }
                }

                if (span_set_attributes(span, otel_span->n_attributes,
                                        otel_span->attributes) != 0 ||
                    span_set_events(span, otel_span->n_events, otel_span->events) != 0) {
                    return decode_opentelemetry_error(
                        service_request, ctr, CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD);
                }

                ctr_span_set_dropped_attributes_count(span, otel_span->dropped_attributes_count);
                ctr_span_set_dropped_events_count(span, otel_span->dropped_events_count);
                ctr_span_set_dropped_links_count(span, otel_span->dropped_links_count);

                if (ctr_span_set_links(span, otel_span->n_links, otel_span->links) != 0) {
                    return decode_opentelemetry_error(
                        service_request, ctr, CTR_DECODE_OPENTELEMETRY_INVALID_PAYLOAD);
                }
            }
        }
    }

    *offset += opentelemetry__proto__collector__trace__v1__export_trace_service_request__get_packed_size(service_request);

    opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(service_request, NULL);

    *out_ctr = ctr;

    return CTR_DECODE_OPENTELEMETRY_SUCCESS;
}

void ctr_decode_opentelemetry_destroy(struct ctrace *ctr)
{
    ctr_destroy(ctr);
}
