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

#include <ctraces/ctraces.h>
#include <fluent-otel-proto/fluent-otel.h>

static void destroy_scope_spans(Opentelemetry__Proto__Trace__V1__ScopeSpans **scope_spans,
                         size_t count);

static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_to_otlp_any_value(struct cfl_variant *value);
static inline Opentelemetry__Proto__Common__V1__KeyValue *ctr_variant_kvpair_to_otlp_kvpair(struct cfl_kvpair *input_pair);
static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_kvlist_to_otlp_any_value(struct cfl_variant *value);

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value);
static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair);
static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist);
static inline void otlp_array_destroy(Opentelemetry__Proto__Common__V1__ArrayValue *array);

static inline void otlp_kvpair_list_destroy(Opentelemetry__Proto__Common__V1__KeyValue **pair_list, size_t entry_count);

static void destroy_spans(Opentelemetry__Proto__Trace__V1__Span **spans, size_t count);

static inline void otlp_kvpair_destroy(Opentelemetry__Proto__Common__V1__KeyValue *kvpair)
{
    if (kvpair != NULL) {
        if (kvpair->key != NULL) {
            free(kvpair->key);
        }

        if (kvpair->value != NULL) {
            otlp_any_value_destroy(kvpair->value);
        }

        free(kvpair);
    }
}

static inline void otlp_kvlist_destroy(Opentelemetry__Proto__Common__V1__KeyValueList *kvlist)
{
    size_t index;

    if (kvlist != NULL) {
        if (kvlist->values != NULL) {
            for (index = 0 ; index < kvlist->n_values ; index++) {
                otlp_kvpair_destroy(kvlist->values[index]);
            }

            free(kvlist->values);
        }

        free(kvlist);
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

            free(array->values);
        }

        free(array);
    }
}

static inline void otlp_any_value_destroy(Opentelemetry__Proto__Common__V1__AnyValue *value)
{
    if (value != NULL) {
        if (value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE) {
            if (value->string_value != NULL) {
                free(value->string_value);
                value->string_value = NULL;
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
                free(value->bytes_value.data);
            }
        }

        free(value);
        value = NULL;
    }
}

static inline Opentelemetry__Proto__Common__V1__KeyValue **otlp_kvpair_list_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValue **result;

    result = \
        calloc(entry_count, sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

    if (result == NULL) {
        ctr_errno();
        return NULL;
    }

    return result;
}


static Opentelemetry__Proto__Common__V1__ArrayValue *otlp_array_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__ArrayValue *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__ArrayValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__array_value__init(value);

        if (entry_count > 0) {
            value->values = \
                calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__AnyValue *));

            if (value->values == NULL) {
                free(value);

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

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValue));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value__init(value);
    }

    return value;
}

static Opentelemetry__Proto__Common__V1__KeyValueList *otlp_kvlist_value_initialize(size_t entry_count)
{
    Opentelemetry__Proto__Common__V1__KeyValueList *value;

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__KeyValueList));

    if (value != NULL) {
        opentelemetry__proto__common__v1__key_value_list__init(value);

        if (entry_count > 0) {
            value->values = \
                calloc(entry_count,
                       sizeof(Opentelemetry__Proto__Common__V1__KeyValue *));

            if (value->values == NULL) {
                free(value);

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

    value = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__AnyValue));

    if (value == NULL) {
        return NULL;
    }

    opentelemetry__proto__common__v1__any_value__init(value);

    if (data_type == CFL_VARIANT_STRING) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else if (data_type == CFL_VARIANT_BOOL) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    }
    else if (data_type == CFL_VARIANT_INT) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    }
    else if (data_type == CFL_VARIANT_DOUBLE) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_DOUBLE_VALUE;
    }
    else if (data_type == CFL_VARIANT_ARRAY) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE;

        value->array_value = otlp_array_value_initialize(entry_count);

        if (value->array_value == NULL) {
            free(value);

            value = NULL;
        }
    }
    else if (data_type == CFL_VARIANT_KVLIST) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_KVLIST_VALUE;

        value->kvlist_value = otlp_kvlist_value_initialize(entry_count);

        if (value->kvlist_value == NULL) {
            free(value);

            value = NULL;
        }
    }
    else if (data_type == CFL_VARIANT_BYTES) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BYTES_VALUE;
    }
    else if (data_type == CFL_VARIANT_REFERENCE) {
        value->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    }
    else {
        free(value);

        value = NULL;
    }

    return value;
}

static inline Opentelemetry__Proto__Common__V1__KeyValue *ctr_variant_kvpair_to_otlp_kvpair(struct cfl_kvpair *input_pair)
{
    Opentelemetry__Proto__Common__V1__KeyValue *kv;

    kv = otlp_kvpair_value_initialize();
    if (kv == NULL) {
        ctr_errno();
        return NULL;
    }

    kv->key = strdup(input_pair->key);
    if (kv->key == NULL) {
        ctr_errno();
        free(kv);
        return NULL;
    }

    kv->value = ctr_variant_to_otlp_any_value(input_pair->val);
    if (kv->value == NULL) {
        ctr_errno();
        free(kv->key);
        free(kv);
        return NULL;
    }

    return kv;
}

static inline void otlp_kvpair_list_destroy(Opentelemetry__Proto__Common__V1__KeyValue **pair_list, size_t entry_count)
{
    size_t index;

    if (pair_list != NULL) {
        for (index = 0 ; index < entry_count ; index++) {
            otlp_kvpair_destroy(pair_list[index]);
        }

        free(pair_list);
        pair_list = NULL;
    }
}

static inline Opentelemetry__Proto__Common__V1__KeyValue **ctr_kvlist_to_otlp_kvpair_list(struct cfl_kvlist *kvlist)
{
    size_t                                       entry_count;
    Opentelemetry__Proto__Common__V1__KeyValue  *keyvalue;
    struct cfl_list                             *iterator;
    Opentelemetry__Proto__Common__V1__KeyValue **result;
    struct cfl_kvpair                           *kvpair;
    size_t                                       index;

    entry_count = cfl_kvlist_count(kvlist);

    result = otlp_kvpair_list_initialize(entry_count);

    if (result != NULL) {
        index = 0;

        cfl_list_foreach(iterator, &kvlist->list) {
            kvpair = cfl_list_entry(iterator, struct cfl_kvpair, _head);

            keyvalue = ctr_variant_kvpair_to_otlp_kvpair(kvpair);

            if (keyvalue == NULL) {
                otlp_kvpair_list_destroy(result, entry_count);

                result = NULL;

                break;
            }

            result[index++] = keyvalue;
        }
    }

    return result;
}


static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_kvlist_to_otlp_any_value(struct cfl_variant *value)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__KeyValue *keyvalue;
    struct cfl_list                            *iterator;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    struct cfl_kvpair                          *kvpair;
    struct cfl_kvlist                          *kvlist;
    size_t                                      index;


    kvlist = value->data.as_kvlist;

    entry_count = cfl_kvlist_count(kvlist);

    result = otlp_any_value_initialize(CFL_VARIANT_KVLIST, entry_count);

    if (result != NULL) {
        index = 0;

        cfl_list_foreach(iterator, &kvlist->list) {
            kvpair = cfl_list_entry(iterator, struct cfl_kvpair, _head);

            keyvalue = ctr_variant_kvpair_to_otlp_kvpair(kvpair);

            if (keyvalue == NULL) {
                otlp_any_value_destroy(result);

                result = NULL;

                break;
            }

            result->kvlist_value->values[index++] = keyvalue;
        }
    }

    return result;
}


static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_array_to_otlp_any_value(struct cfl_variant *value)
{
    size_t                                      entry_count;
    Opentelemetry__Proto__Common__V1__AnyValue *entry_value;
    Opentelemetry__Proto__Common__V1__AnyValue *result;
    struct cfl_array                           *array;
    size_t                                      index;

    array = value->data.as_array;

    entry_count = array->entry_count;

    result = otlp_any_value_initialize(CFL_VARIANT_ARRAY, entry_count);

    if (result != NULL) {
        index = 0;

        for (index = 0 ; index < entry_count ; index++) {
            entry_value = ctr_variant_to_otlp_any_value(cfl_array_fetch_by_index(array, index));

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

static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_string_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_STRING, 0);

    if (result != NULL) {
        result->string_value = strdup(value->data.as_string);

        if (result->string_value == NULL) {
            otlp_any_value_destroy(result);
            return NULL;
        }
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_boolean_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_BOOL, 0);

    if (result != NULL) {
        result->bool_value = value->data.as_bool;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_int64_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_INT, 0);

    if (result != NULL) {
        result->int_value = value->data.as_int64;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_double_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_DOUBLE, 0);

    if (result != NULL) {
        result->double_value = value->data.as_double;
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_binary_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    result = otlp_any_value_initialize(CFL_VARIANT_BYTES, 0);

    if (result != NULL) {
        result->bytes_value.len = cfl_sds_len(value->data.as_bytes);
        result->bytes_value.data = calloc(result->bytes_value.len, sizeof(char));

        if (result->bytes_value.data == NULL) {
            otlp_any_value_destroy(result);
            result = NULL;

        }

        memcpy(result->bytes_value.data, value->data.as_bytes, result->bytes_value.len);
    }

    return result;
}

static inline Opentelemetry__Proto__Common__V1__AnyValue *ctr_variant_to_otlp_any_value(struct cfl_variant *value)
{
    Opentelemetry__Proto__Common__V1__AnyValue *result;

    if (value->type == CFL_VARIANT_STRING) {
        result = ctr_variant_string_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_BOOL) {
        result = ctr_variant_boolean_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_INT) {
        result = ctr_variant_int64_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_DOUBLE) {
        result = ctr_variant_double_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        result = ctr_variant_array_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        result = ctr_variant_kvlist_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_BYTES) {
        result = ctr_variant_binary_to_otlp_any_value(value);
    }
    else if (value->type == CFL_VARIANT_REFERENCE) {
        result = ctr_variant_string_to_otlp_any_value(value);
    }
    else {
        result = NULL;
    }

    return result;
}

static Opentelemetry__Proto__Common__V1__KeyValue **set_attributes_from_ctr(struct ctrace_attributes *attr)
{
    if(attr == NULL) {
        return NULL;
    }

    return ctr_kvlist_to_otlp_kvpair_list(attr->kv);
}

static Opentelemetry__Proto__Resource__V1__Resource *initialize_resource()
{
    Opentelemetry__Proto__Resource__V1__Resource *resource;

    resource = calloc(1, sizeof(Opentelemetry__Proto__Resource__V1__Resource));

    if (!resource) {
        ctr_errno();
        return NULL;
    }

    opentelemetry__proto__resource__v1__resource__init(resource);

    return resource;
}

static size_t get_attributes_count(struct ctrace_attributes *attr)
{
    if (attr == NULL) {
        return 0;
    }

    return cfl_kvlist_count(attr->kv);
}

static Opentelemetry__Proto__Resource__V1__Resource *ctr_set_resource(struct ctrace_resource *resource)
{
    Opentelemetry__Proto__Resource__V1__Resource *otel_resource;

    otel_resource = initialize_resource();
    if (!otel_resource) {
        return NULL;
    }

    otel_resource->n_attributes = get_attributes_count(resource->attr);
    otel_resource->attributes = set_attributes_from_ctr(resource->attr);
    otel_resource->dropped_attributes_count = resource->dropped_attr_count;

    return otel_resource;
}

static void otel_span_set_trace_id(Opentelemetry__Proto__Trace__V1__Span *span,
                                   struct ctrace_id *trace_id)
{
    size_t len;
    uint8_t *trace_id_str;

    if (!trace_id) {
        return;
    }

    len = ctr_id_get_len(trace_id);
    trace_id_str = ctr_id_get_buf(trace_id);

    span->trace_id.len = len;
    span->trace_id.data = trace_id_str;
}

static void otel_span_set_span_id(Opentelemetry__Proto__Trace__V1__Span *span,
                                  struct ctrace_id *span_id)
{
    size_t len;
    uint8_t *span_id_str;

    if (!span_id) {
        return;
    }

    len = ctr_id_get_len(span_id);
    span_id_str = ctr_id_get_buf(span_id);

    span->span_id.len = len;
    span->span_id.data = span_id_str;
}

static void otel_span_set_parent_span_id(Opentelemetry__Proto__Trace__V1__Span *span,
                                         struct ctrace_id *parent)
{
    size_t len;
    uint8_t *parent_id_str;

    if (!parent) {
        return;
    }

    len = ctr_id_get_len(parent);
    parent_id_str = ctr_id_get_buf(parent);

    span->parent_span_id.len = len;
    span->parent_span_id.data = parent_id_str;
}

static void otel_span_set_kind(Opentelemetry__Proto__Trace__V1__Span *otel_span,
                               int kind)
{
    switch (kind) {
    case CTRACE_SPAN_INTERNAL:
        otel_span->kind = OPENTELEMETRY__PROTO__TRACE__V1__SPAN__SPAN_KIND__SPAN_KIND_INTERNAL;
        break;
    case CTRACE_SPAN_SERVER:
        otel_span->kind = OPENTELEMETRY__PROTO__TRACE__V1__SPAN__SPAN_KIND__SPAN_KIND_SERVER;
        break;
    case CTRACE_SPAN_CLIENT:
        otel_span->kind = OPENTELEMETRY__PROTO__TRACE__V1__SPAN__SPAN_KIND__SPAN_KIND_CLIENT;
        break;
    case CTRACE_SPAN_PRODUCER:
        otel_span->kind = OPENTELEMETRY__PROTO__TRACE__V1__SPAN__SPAN_KIND__SPAN_KIND_PRODUCER;
        break;
    case CTRACE_SPAN_CONSUMER:
        otel_span->kind = OPENTELEMETRY__PROTO__TRACE__V1__SPAN__SPAN_KIND__SPAN_KIND_CONSUMER;
        break;
    default:
        otel_span->kind = OPENTELEMETRY__PROTO__TRACE__V1__SPAN__SPAN_KIND__SPAN_KIND_UNSPECIFIED;
        break;
    }
}

static void otel_span_set_start_time(Opentelemetry__Proto__Trace__V1__Span *span,
                                     uint64_t start_time)
{
    span->start_time_unix_nano = start_time;
}

static void otel_span_set_end_time(Opentelemetry__Proto__Trace__V1__Span *span,
                                   uint64_t end_time)
{
    span->end_time_unix_nano = end_time;
}

static void otel_span_set_attributes(Opentelemetry__Proto__Trace__V1__Span *span,
                                     struct ctrace_attributes *attr)
{
    span->n_attributes = get_attributes_count(attr);
    span->attributes = set_attributes_from_ctr(attr);
}

static void otel_span_set_dropped_attributes_count(Opentelemetry__Proto__Trace__V1__Span *span,
                                                   uint32_t dropped_attr_count)
{
    span->dropped_attributes_count = dropped_attr_count;
}

static Opentelemetry__Proto__Trace__V1__Span__Event *set_event(struct ctrace_span_event *ctr_event)
{
    Opentelemetry__Proto__Trace__V1__Span__Event *event;

    event = calloc(1, sizeof(Opentelemetry__Proto__Trace__V1__Span__Event));
    opentelemetry__proto__trace__v1__span__event__init(event);

    event->time_unix_nano = ctr_event->time_unix_nano;
    event->name = ctr_event->name;
    event->n_attributes = ctr_attributes_count(ctr_event->attr);
    event->attributes = set_attributes_from_ctr(ctr_event->attr);
    event->dropped_attributes_count = ctr_event->dropped_attr_count;

    return event;
}

static Opentelemetry__Proto__Trace__V1__Span__Event **set_events_from_ctr(struct cfl_list *events)
{
    int count;
    int event_index;
    struct cfl_list *head;
    struct ctrace_span_event *ctr_event;

    count = cfl_list_size(events);

    Opentelemetry__Proto__Trace__V1__Span__Event **event_arr;

    event_arr = calloc(count, sizeof(Opentelemetry__Proto__Trace__V1__Span__Event *));

    event_index = 0;
    cfl_list_foreach(head, events) {
        ctr_event = cfl_list_entry(head, struct ctrace_span_event, _head);
        event_arr[event_index++] = set_event(ctr_event);
    }

    return event_arr;
}

static void otel_span_set_events(Opentelemetry__Proto__Trace__V1__Span *otel_span,
                                 struct cfl_list *events)
{
    otel_span->n_events = cfl_list_size(events);
    otel_span->events = set_events_from_ctr(events);
}

static void otel_span_set_dropped_events_count(Opentelemetry__Proto__Trace__V1__Span *span,
                                               uint32_t dropped_events_count)
{
    span->dropped_events_count = dropped_events_count;
}

static void otel_span_set_name(Opentelemetry__Proto__Trace__V1__Span *otel_span,
                               char *name)
{
    otel_span->name = name;
}

static void otel_span_set_trace_state(Opentelemetry__Proto__Trace__V1__Span *otel_span,
                                      char *trace_state)
{
    otel_span->trace_state = trace_state;
}

static void otel_span_set_status(Opentelemetry__Proto__Trace__V1__Span *otel_span,
                                 struct ctrace_span_status status)
{
    Opentelemetry__Proto__Trace__V1__Status *otel_status;

    otel_status = calloc(1, sizeof(Opentelemetry__Proto__Trace__V1__Status));
    opentelemetry__proto__trace__v1__status__init(otel_status);

    otel_status->code = status.code;
    otel_status->message = status.message;

    otel_span->status = otel_status;
}

static void otel_span_set_links(Opentelemetry__Proto__Trace__V1__Span *otel_span,
                                struct cfl_list *links)
{
    int count;
    int link_index;
    struct cfl_list *head;
    struct ctrace_link *link;
    size_t link_span_id_size;
    size_t link_trace_id_size;
    uint8_t *link_trace_id;
    uint8_t *link_span_id;

    count = cfl_list_size(links);

    Opentelemetry__Proto__Trace__V1__Span__Link **otel_links;
    Opentelemetry__Proto__Trace__V1__Span__Link *otel_link;

    otel_links = calloc(count, sizeof(Opentelemetry__Proto__Trace__V1__Span__Link *));

    link_index = 0;

    cfl_list_foreach(head, links) {
        link = cfl_list_entry(head, struct ctrace_link, _head);

        otel_link = calloc(1, sizeof(Opentelemetry__Proto__Trace__V1__Span__Link));
        opentelemetry__proto__trace__v1__span__link__init(otel_link);

        if (link->trace_id) {
            link_trace_id_size = ctr_id_get_len(link->trace_id);
            link_trace_id = ctr_id_get_buf(link->trace_id);

            otel_link->trace_id.len = link_trace_id_size;
            otel_link->trace_id.data = link_trace_id;
        }

        if (link->span_id) {
            link_span_id_size = ctr_id_get_len(link->span_id);
            link_span_id = ctr_id_get_buf(link->span_id);

            otel_link->span_id.len = link_span_id_size;
            otel_link->span_id.data = link_span_id;
        }

        otel_link->trace_state = link->trace_state;

        otel_link->n_attributes = get_attributes_count(link->attr);
        otel_link->attributes = set_attributes_from_ctr(link->attr);
        otel_link->dropped_attributes_count = link->dropped_attr_count;

        otel_links[link_index++] = otel_link;
    }

    otel_span->n_links = count;
    otel_span->links = otel_links;
}

static void set_span(Opentelemetry__Proto__Trace__V1__Span *otel_span,
                     struct ctrace_span *span)
{
    otel_span_set_name(otel_span, span->name);
    otel_span_set_trace_id(otel_span, span->trace_id);
    otel_span_set_span_id(otel_span, span->span_id);
    otel_span_set_parent_span_id(otel_span, span->parent_span_id);
    otel_span_set_kind(otel_span, span->kind);
    otel_span_set_trace_state(otel_span, span->trace_state);
    otel_span_set_start_time(otel_span, span->start_time_unix_nano);
    otel_span_set_end_time(otel_span, span->end_time_unix_nano);
    otel_span_set_status(otel_span, span->status);

    otel_span_set_attributes(otel_span, span->attr);
    otel_span_set_dropped_attributes_count(otel_span, span->dropped_attr_count);
    otel_span_set_events(otel_span, &span->events);
    otel_span_set_dropped_events_count(otel_span, span->dropped_events_count);
    otel_span_set_links(otel_span, &span->links);
}

static Opentelemetry__Proto__Trace__V1__Span **initialize_spans(size_t span_count)
{
    Opentelemetry__Proto__Trace__V1__Span **spans;

    spans = calloc(span_count, sizeof(Opentelemetry__Proto__Trace__V1__Span *));
    if (!spans) {
        ctr_errno();
        return NULL;
    }

    return spans;
}

static Opentelemetry__Proto__Trace__V1__Span *initialize_span()
{
    Opentelemetry__Proto__Trace__V1__Span *span;

    span = calloc(1, sizeof(Opentelemetry__Proto__Trace__V1__Span));
    if (!span) {
        ctr_errno();
        return NULL;
    }

    opentelemetry__proto__trace__v1__span__init(span);

    return span;
}

static Opentelemetry__Proto__Trace__V1__Span **set_spans(struct ctrace_scope_span *scope_span)
{
    int span_count;
    int span_index;
    struct cfl_list *head;
    struct ctrace_span *span;

    Opentelemetry__Proto__Trace__V1__Span **spans;
    Opentelemetry__Proto__Trace__V1__Span *otel_span;

    span_count = cfl_list_size(&scope_span->spans);
    spans = initialize_spans(span_count);
    if (!spans) {
        return NULL;
    }

    span_index = 0;

    cfl_list_foreach(head, &scope_span->spans) {
        span = cfl_list_entry(head, struct ctrace_span, _head);

        otel_span = initialize_span();
        if (!otel_span) {
            if (span_index > 0) {
                destroy_spans(spans, span_index);
            }
            return NULL;
        }

        set_span(otel_span, span);
        spans[span_index++] = otel_span;
    }

    return spans;
}

static Opentelemetry__Proto__Common__V1__InstrumentationScope *initialize_instrumentation_scope()
{
    Opentelemetry__Proto__Common__V1__InstrumentationScope *instrumentation_scope;

    instrumentation_scope = calloc(1, sizeof(Opentelemetry__Proto__Common__V1__InstrumentationScope));
    if (!instrumentation_scope) {
        ctr_errno();
        return NULL;
    }
    opentelemetry__proto__common__v1__instrumentation_scope__init(instrumentation_scope);

    return instrumentation_scope;
}

static Opentelemetry__Proto__Common__V1__InstrumentationScope *set_instrumentation_scope(struct ctrace_instrumentation_scope *instrumentation_scope)
{
    Opentelemetry__Proto__Common__V1__InstrumentationScope *otel_scope;

    otel_scope = initialize_instrumentation_scope();
    if (!otel_scope) {
        return NULL;
    }

    if (instrumentation_scope->name) {
        otel_scope->name = instrumentation_scope->name;
    }
    else {
        otel_scope->name = "";
    }
    if (instrumentation_scope->version) {
        otel_scope->version = instrumentation_scope->version;
    }
    else {
        otel_scope->version = "";
    }
    otel_scope->n_attributes = get_attributes_count(instrumentation_scope->attr);
    otel_scope->dropped_attributes_count = instrumentation_scope->dropped_attr_count;
    otel_scope->attributes = set_attributes_from_ctr(instrumentation_scope->attr);

    return otel_scope;
}

static Opentelemetry__Proto__Trace__V1__ScopeSpans **initialize_scope_spans(size_t count)
{
    Opentelemetry__Proto__Trace__V1__ScopeSpans **scope_spans;

    scope_spans = calloc(count, sizeof(Opentelemetry__Proto__Trace__V1__ScopeSpans *));
    if (!scope_spans) {
        ctr_errno();
        return NULL;
    }

    return scope_spans;
}

static Opentelemetry__Proto__Trace__V1__ScopeSpans *initialize_scope_span()
{
    Opentelemetry__Proto__Trace__V1__ScopeSpans *scope_span;

    scope_span = calloc(1, sizeof(Opentelemetry__Proto__Trace__V1__ScopeSpans));
    if (!scope_span) {
        ctr_errno();
        return NULL;
    }

    opentelemetry__proto__trace__v1__scope_spans__init(scope_span);

    return scope_span;
}

static Opentelemetry__Proto__Trace__V1__ScopeSpans **set_scope_spans(struct ctrace_resource_span *resource_span)
{
    int span_count;
    int scope_span_count;
    int scope_span_index;
    struct cfl_list *head;
    struct ctrace_scope_span *scope_span;

    Opentelemetry__Proto__Trace__V1__ScopeSpans **scope_spans;
    Opentelemetry__Proto__Trace__V1__ScopeSpans *otel_scope_span;


    scope_span_count = cfl_list_size(&resource_span->scope_spans);
    scope_spans = initialize_scope_spans(scope_span_count);
    if (!scope_spans) {
        return NULL;
    }

    scope_span_index = 0;

    cfl_list_foreach(head, &resource_span->scope_spans) {
        scope_span = cfl_list_entry(head, struct ctrace_scope_span, _head);

        otel_scope_span = initialize_scope_span();
        if (!otel_scope_span) {
            if (scope_span_index > 0) {
                destroy_scope_spans(scope_spans, scope_span_index - 1);
            }
            /* note: scope_spans is freed inside destroy_scope_spans() */
            return NULL;
        }

        otel_scope_span->schema_url = scope_span->schema_url;
        if (scope_span->instrumentation_scope != NULL) {
            otel_scope_span->scope = set_instrumentation_scope(scope_span->instrumentation_scope);
        }

        span_count = cfl_list_size(&scope_span->spans);
        otel_scope_span->n_spans = span_count;
        otel_scope_span->spans = set_spans(scope_span);

        scope_spans[scope_span_index++] = otel_scope_span;
    }

    return scope_spans;
}

static Opentelemetry__Proto__Trace__V1__ResourceSpans **initialize_resource_spans(size_t count)
{
    Opentelemetry__Proto__Trace__V1__ResourceSpans **resource_spans;

    resource_spans = calloc(count, sizeof(Opentelemetry__Proto__Trace__V1__ResourceSpans *));
    if (!resource_spans) {
        ctr_errno();
        return NULL;
    }

    return resource_spans;
}

static Opentelemetry__Proto__Trace__V1__ResourceSpans *initialize_resource_span()
{
    Opentelemetry__Proto__Trace__V1__ResourceSpans *resource_span;

    resource_span = calloc(1, sizeof(Opentelemetry__Proto__Trace__V1__ResourceSpans));
    if (!resource_span) {
        ctr_errno();
        return NULL;
    }

    opentelemetry__proto__trace__v1__resource_spans__init(resource_span);

    return resource_span;
}


static Opentelemetry__Proto__Trace__V1__ResourceSpans **set_resource_spans(struct ctrace *ctr)
{
    struct ctrace_resource_span *resource_span;
    struct cfl_list *head;
    int resource_span_count;
    int resource_span_index;

    Opentelemetry__Proto__Trace__V1__ResourceSpans **rs;
    Opentelemetry__Proto__Trace__V1__ResourceSpans *otel_resource_span;
    Opentelemetry__Proto__Trace__V1__ScopeSpans **scope_spans;

    resource_span_count = cfl_list_size(&ctr->resource_spans);
    rs = initialize_resource_spans(resource_span_count);

    resource_span_index = 0;

    cfl_list_foreach(head, &ctr->resource_spans) {
        resource_span = cfl_list_entry(head, struct ctrace_resource_span, _head);

        otel_resource_span = initialize_resource_span();
        if (!otel_resource_span) {
            free(rs);
            return NULL;
        }
        otel_resource_span->resource = ctr_set_resource(resource_span->resource);

        otel_resource_span->n_scope_spans = cfl_list_size(&resource_span->scope_spans);
        scope_spans = set_scope_spans(resource_span);
        otel_resource_span->scope_spans = scope_spans;

        otel_resource_span->schema_url = resource_span->schema_url;
        rs[resource_span_index++] = otel_resource_span;
    }

    return rs;

}

static Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *initialize_export_service_request()
{
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *req;

    req = malloc(sizeof(Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest));
    if (!req) {
        ctr_errno();
        return NULL;
    }
    opentelemetry__proto__collector__trace__v1__export_trace_service_request__init(req);

    return req;
}

static Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *create_export_service_request(struct ctrace *ctr)
{
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *req;
    Opentelemetry__Proto__Trace__V1__ResourceSpans **rs;

    req = initialize_export_service_request();
    if (!req) {
        return NULL;
    }

    req->n_resource_spans = cfl_list_size(&ctr->resource_spans);
    rs = set_resource_spans(ctr);
    req->resource_spans = rs;

    return req;
}

static void destroy_attributes(Opentelemetry__Proto__Common__V1__KeyValue **attributes, size_t count)
{
    otlp_kvpair_list_destroy(attributes, count);
}

static void destroy_resource(Opentelemetry__Proto__Resource__V1__Resource *resource)
{
    destroy_attributes(resource->attributes, resource->n_attributes);

    resource->attributes = NULL;
    resource->n_attributes = 0;
    resource->dropped_attributes_count = 0;

    free(resource);
}

static void destroy_id(ProtobufCBinaryData id){
    id.len = 0;

    if (id.data) {
        id.data = NULL;
    }
}

static void destroy_event(Opentelemetry__Proto__Trace__V1__Span__Event *event)
{
    destroy_attributes(event->attributes, event->n_attributes);

    event->time_unix_nano = 0;
    event->name = NULL;
    event->attributes = NULL;
    event->n_attributes = 0;
    event->dropped_attributes_count = 0;

    free(event);
}

static void destroy_events(Opentelemetry__Proto__Trace__V1__Span__Event **events, size_t count)
{
    int event_index;
    Opentelemetry__Proto__Trace__V1__Span__Event *event;

    for (event_index = 0; event_index < count; event_index++) {
        event = events[event_index];
        destroy_event(event);
    }

    free(events);
}

static void destroy_link(Opentelemetry__Proto__Trace__V1__Span__Link *link)
{
    destroy_attributes(link->attributes, link->n_attributes);

    destroy_id(link->trace_id);
    destroy_id(link->span_id);

    link->trace_state = NULL;
    link->attributes = NULL;
    link->n_attributes = 0;
    link->dropped_attributes_count = 0;

    free(link);
}


static void destroy_links(Opentelemetry__Proto__Trace__V1__Span__Link **links, size_t count)
{
    int link_index;
    Opentelemetry__Proto__Trace__V1__Span__Link *link;

    for (link_index = 0; link_index < count; link_index++) {
        link = links[link_index];
        destroy_link(link);
    }

    free(links);
}

static void destroy_span(Opentelemetry__Proto__Trace__V1__Span *span)
{
    destroy_events(span->events, span->n_events);
    destroy_attributes(span->attributes, span->n_attributes);
    destroy_links(span->links, span->n_links);

    span->attributes = NULL;
    span->n_attributes = 0;
    span->dropped_attributes_count = 0;

    span->events = NULL;
    span->n_events = 0;
    span->dropped_events_count = 0;

    span->links = NULL;
    span->n_links = 0;
    span->dropped_links_count = 0;

    span->start_time_unix_nano = 0;
    span->end_time_unix_nano = 0;

    destroy_id(span->trace_id);
    destroy_id(span->span_id);
    destroy_id(span->parent_span_id);
    span->trace_state = NULL;

    span->name = NULL;
    span->kind = 0;

    span->status->message = NULL;
    span->status->code = 0;
    free(span->status);

    free(span);
}

static void destroy_spans(Opentelemetry__Proto__Trace__V1__Span **spans, size_t count)
{
    int span_index;

    for (span_index = 0; span_index < count; span_index++) {
        destroy_span(spans[span_index]);
    }

    free(spans);
}

static void destroy_scope(Opentelemetry__Proto__Common__V1__InstrumentationScope *scope)
{
    if (scope->name) {
        scope->name = NULL;
    }

    scope->version = NULL;

    destroy_attributes(scope->attributes, scope->n_attributes);
    scope->attributes = NULL;
    scope->n_attributes = 0;
    scope->dropped_attributes_count = 0;

    free(scope);
}

static void destroy_scope_span(Opentelemetry__Proto__Trace__V1__ScopeSpans *scope_span)
{
    if (scope_span->schema_url) {
        scope_span->schema_url = NULL;
    }

    if (scope_span->scope) {
        destroy_scope(scope_span->scope);
    }

    destroy_spans(scope_span->spans, scope_span->n_spans);
    scope_span->spans = NULL;
    scope_span->n_spans = 0;

    free(scope_span);
}

static void destroy_scope_spans(Opentelemetry__Proto__Trace__V1__ScopeSpans **scope_spans,
                         size_t count)
{
    int scope_span_index;
    Opentelemetry__Proto__Trace__V1__ScopeSpans *scope_span;

    for (scope_span_index = 0; scope_span_index < count; scope_span_index++) {
        scope_span = scope_spans[scope_span_index];
        destroy_scope_span(scope_span);
    }

    free(scope_spans);
}

static void destroy_resource_spans(Opentelemetry__Proto__Trace__V1__ResourceSpans **rs,
                            int resource_span_count)
{
    Opentelemetry__Proto__Trace__V1__ResourceSpans *resource_span;
    int resource_span_index;

    for(resource_span_index = 0; resource_span_index < resource_span_count; resource_span_index++) {
        resource_span = rs[resource_span_index];

        destroy_resource(resource_span->resource);
        resource_span->resource = NULL;

        destroy_scope_spans(resource_span->scope_spans, resource_span->n_scope_spans);
        resource_span->scope_spans = NULL;
        resource_span->n_scope_spans = 0;
        resource_span->schema_url = NULL;

        free(resource_span);
    }
    free(rs);
}

static void destroy_export_service_request(Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *req)
{
    destroy_resource_spans(req->resource_spans, req->n_resource_spans);
    req->n_resource_spans = 0;
    req->resource_spans = NULL;

    free(req);
    req = NULL;
}

cfl_sds_t ctr_encode_opentelemetry_create(struct ctrace *ctr)
{
    cfl_sds_t buf;
    size_t len;
    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *req;

    req = create_export_service_request(ctr);

    len = opentelemetry__proto__collector__trace__v1__export_trace_service_request__get_packed_size(req);
    buf = cfl_sds_create_size(len);
    if (!buf) {
        destroy_export_service_request(req);
        return NULL;
    }
    cfl_sds_set_len(buf, len);

    opentelemetry__proto__collector__trace__v1__export_trace_service_request__pack(req, (uint8_t *)buf);
    destroy_export_service_request(req);

    return buf;
}

void ctr_encode_opentelemetry_destroy(cfl_sds_t text)
{
    cfl_sds_destroy(text);
}
