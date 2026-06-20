/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CTraces
 *  =======
 *  Copyright 2022 Eduardo Silva <eduardo@calyptia.com>
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
#include <ctraces/ctr_mpack_utils.h>
#include <ctraces/ctr_decode_msgpack.h>
#include <cfl/cfl_sds.h>
#include <ctraces/ctr_variant_utils.h>


/* Resource callbacks */

static int unpack_resource_dropped_attributes_count(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint32_tag(
            reader, &context->resource->dropped_attr_count);
}

static int unpack_resource_attributes(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct cfl_kvlist                 *attributes;
    int                                result;

    if (ctr_mpack_peek_type(reader) == mpack_type_nil) {
        result = ctr_mpack_consume_nil_tag(reader);
    }
    else {
        result = unpack_cfl_kvlist(reader, &attributes);

        if (result == 0) {
            cfl_kvlist_destroy(context->resource->attr->kv);

            context->resource->attr->kv = attributes;
        }
    }

    return result;
}

static int unpack_resource(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"attributes",               unpack_resource_attributes},
            {"dropped_attributes_count", unpack_resource_dropped_attributes_count},
            {NULL,                       NULL}
        };

    return ctr_mpack_unpack_map(reader, callbacks, ctx);
}


/* Instrumentation scope callbacks */

static int unpack_instrumentation_scope_name(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_string_or_nil_tag(
            reader,
            &context->scope_span->instrumentation_scope->name);
}

static int unpack_instrumentation_scope_version(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_string_or_nil_tag(
            reader,
            &context->scope_span->instrumentation_scope->version);
}

static int unpack_instrumentation_scope_dropped_attribute_count(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint32_tag(
            reader,
            &context->scope_span->instrumentation_scope->dropped_attr_count);
}

static int unpack_instrumentation_scope_attributes(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct ctrace_attributes          *attributes;
    int                                result;

    if (ctr_mpack_peek_type(reader) == mpack_type_nil) {
        result = ctr_mpack_consume_nil_tag(reader);
    }
    else {
        attributes = ctr_attributes_create();
        if (attributes == NULL) {
            return CTR_DECODE_MSGPACK_VARIANT_DECODE_ERROR;
        }

        cfl_kvlist_destroy(attributes->kv);

        attributes->kv = NULL;

        result = unpack_cfl_kvlist(reader, &attributes->kv);

        if (result != 0) {
            ctr_attributes_destroy(attributes);
            return CTR_DECODE_MSGPACK_VARIANT_DECODE_ERROR;
        }

        if (context->scope_span->instrumentation_scope->attr != NULL) {
            ctr_attributes_destroy(context->scope_span->instrumentation_scope->attr);
            context->scope_span->instrumentation_scope->attr = NULL;
        }

        context->scope_span->instrumentation_scope->attr = attributes;
    }

    return CTR_DECODE_MSGPACK_SUCCESS;
}

static int unpack_scope_span_instrumentation_scope(mpack_reader_t *reader, size_t index, void *ctx)
{
    mpack_type_t                          tag_type;
    int                                   result;
    struct ctrace_instrumentation_scope  *instrumentation_scope;
    struct ctr_msgpack_decode_context    *context = ctx;
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"name",                     unpack_instrumentation_scope_name},
            {"version",                  unpack_instrumentation_scope_version},
            {"attributes",               unpack_instrumentation_scope_attributes},
            {"dropped_attributes_count", unpack_instrumentation_scope_dropped_attribute_count},
            {NULL,                       NULL}
        };

    tag_type = ctr_mpack_peek_type(reader);

    if (tag_type == mpack_type_nil) {
        return ctr_mpack_consume_nil_tag(reader);
    }

    instrumentation_scope = ctr_instrumentation_scope_create(NULL, NULL, 0, NULL);

    if (instrumentation_scope == NULL) {
        return CTR_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    ctr_scope_span_set_instrumentation_scope(context->scope_span, instrumentation_scope);

    result = ctr_mpack_unpack_map(reader, callbacks, ctx);

    if (result != CTR_DECODE_MSGPACK_SUCCESS) {
        ctr_instrumentation_scope_destroy(context->scope_span->instrumentation_scope);
        context->scope_span->instrumentation_scope = NULL;
    }

    return result;
}

/* Event callbacks */

static int unpack_event_name(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    if (context->event->name != NULL) {
        cfl_sds_destroy(context->event->name);

        context->event->name = NULL;
    }

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->event->name);
}

static int unpack_event_time_unix_nano(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint64_tag(reader, &context->event->time_unix_nano);
}

static int unpack_event_attributes(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct cfl_kvlist                 *attributes;
    int                                result;

    if (ctr_mpack_peek_type(reader) == mpack_type_nil) {
        ctr_mpack_consume_nil_tag(reader);

        return CTR_DECODE_MSGPACK_SUCCESS;
    }

    result = unpack_cfl_kvlist(reader, &attributes);

    if (result != 0) {
        return CTR_DECODE_MSGPACK_VARIANT_DECODE_ERROR;
    }

    cfl_kvlist_destroy(context->event->attr->kv);
    context->event->attr->kv = attributes;

    return CTR_DECODE_MSGPACK_SUCCESS;
}

static int unpack_event_dropped_attributes_count(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint32_tag(reader, &context->event->dropped_attr_count);
}

static int unpack_event(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context    *context = ctx;
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"name",                     unpack_event_name},
            {"time_unix_nano",           unpack_event_time_unix_nano},
            {"attributes",               unpack_event_attributes},
            {"dropped_attributes_count", unpack_event_dropped_attributes_count},
            {NULL,                       NULL}
        };

    context->event = ctr_span_event_add(context->span, "");

    if (context->event == NULL) {
        return CTR_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    return ctr_mpack_unpack_map(reader, callbacks, ctx);
}

/* Link callbacks */

static int unpack_link_trace_id(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    int                                result;
    cfl_sds_t                          value;

    result = ctr_mpack_consume_string_or_nil_tag(reader, &value);

    if (result == CTR_MPACK_SUCCESS && value != NULL) {
        context->link->trace_id = ctr_id_from_base16(value);

        if (context->link->trace_id == NULL) {
            result = CTR_MPACK_CORRUPT_INPUT_DATA_ERROR;
        }

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_link_span_id(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    int                                result;
    cfl_sds_t                          value;

    result = ctr_mpack_consume_string_or_nil_tag(reader, &value);

    if (result == CTR_MPACK_SUCCESS && value != NULL) {
        context->link->span_id = ctr_id_from_base16(value);

        if (context->link->span_id == NULL) {
            result = CTR_MPACK_CORRUPT_INPUT_DATA_ERROR;
        }

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_link_trace_state(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->link->trace_state);
}

static int unpack_link_dropped_attributes_count(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint32_tag(reader, &context->link->dropped_attr_count);
}

static int unpack_link_attributes(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct cfl_kvlist                 *attributes;
    int                                result;

    if (ctr_mpack_peek_type(reader) == mpack_type_nil) {
        result = ctr_mpack_consume_nil_tag(reader);
    }
    else {
        result = unpack_cfl_kvlist(reader, &attributes);

        if (result == 0) {
            if (context->link->attr == NULL) {
                context->link->attr = ctr_attributes_create();
            }

            if (context->link->attr->kv != NULL) {
                cfl_kvlist_destroy(context->link->attr->kv);
            }

            context->link->attr->kv = attributes;

            result = CTR_DECODE_MSGPACK_SUCCESS;
        }
        else {
            result = CTR_DECODE_MSGPACK_VARIANT_DECODE_ERROR;
        }
    }

    return result;
}

static int unpack_link(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context    *context = ctx;
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"trace_id",                 unpack_link_trace_id},
            {"span_id",                  unpack_link_span_id},
            {"trace_state",              unpack_link_trace_state},
            {"attributes",               unpack_link_attributes},
            {"dropped_attributes_count", unpack_link_dropped_attributes_count},
            {NULL,                       NULL}
        };

    context->link = ctr_link_create(context->span, NULL, 0, NULL, 0);

    if (context->link == NULL) {
        return CTR_MPACK_ALLOCATION_ERROR;
    }

    return ctr_mpack_unpack_map(reader, callbacks, ctx);
}

/* Span callbacks */

static int unpack_span_trace_id(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct ctrace_id                  *decoded_id;
    int                                result;
    cfl_sds_t                          value;

    result = ctr_mpack_consume_string_or_nil_tag(reader, &value);

    if (result == CTR_MPACK_SUCCESS && value != NULL) {
        decoded_id = ctr_id_from_base16(value);

        if (decoded_id != NULL) {
            ctr_span_set_trace_id_with_cid(context->span, decoded_id);

            ctr_id_destroy(decoded_id);
        }
        else {
            result = CTR_MPACK_CORRUPT_INPUT_DATA_ERROR;
        }

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_span_span_id(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct ctrace_id                  *decoded_id;
    int                                result;
    cfl_sds_t                          value;

    result = ctr_mpack_consume_string_or_nil_tag(reader, &value);

    if (result == CTR_MPACK_SUCCESS && value != NULL) {
        decoded_id = ctr_id_from_base16(value);

        if (decoded_id != NULL) {
            ctr_span_set_span_id_with_cid(context->span, decoded_id);

            ctr_id_destroy(decoded_id);
        }
        else {
            result = CTR_MPACK_CORRUPT_INPUT_DATA_ERROR;
        }

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_span_parent_span_id(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct ctrace_id                  *decoded_id;
    int                                result;
    cfl_sds_t                          value;

    result = ctr_mpack_consume_string_or_nil_tag(reader, &value);

    if (result == CTR_MPACK_SUCCESS && value != NULL) {
        decoded_id = ctr_id_from_base16(value);

        if (decoded_id != NULL) {
            ctr_span_set_parent_span_id_with_cid(context->span, decoded_id);

            ctr_id_destroy(decoded_id);
        }
        else {
            result = CTR_MPACK_CORRUPT_INPUT_DATA_ERROR;
        }

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_span_trace_state(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    if (context->span->trace_state != NULL) {
        cfl_sds_destroy(context->span->trace_state);

        context->span->trace_state = NULL;
    }

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->span->trace_state);
}

static int unpack_span_name(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    if (context->span->name != NULL) {
        cfl_sds_destroy(context->span->name);

        context->span->name = NULL;
    }

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->span->name);
}

static int unpack_span_kind(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_int32_tag(reader, &context->span->kind);
}

static int unpack_span_start_time_unix_nano(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint64_tag(reader, &context->span->start_time_unix_nano);
}

static int unpack_span_end_time_unix_nano(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint64_tag(reader, &context->span->end_time_unix_nano);
}

static int unpack_span_attributes(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;
    struct cfl_kvlist                 *attributes;
    int                                result;

    if (ctr_mpack_peek_type(reader) == mpack_type_nil) {
        ctr_mpack_consume_nil_tag(reader);

        return CTR_DECODE_MSGPACK_SUCCESS;
    }

    result = unpack_cfl_kvlist(reader, &attributes);

    if (result != 0) {
        return CTR_DECODE_MSGPACK_VARIANT_DECODE_ERROR;
    }

    cfl_kvlist_destroy(context->span->attr->kv);
    context->span->attr->kv = attributes;

    return CTR_DECODE_MSGPACK_SUCCESS;
}

static int unpack_span_dropped_attributes_count(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint32_tag(reader, &context->span->dropped_attr_count);
}

static int unpack_span_dropped_events_count(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint32_tag(reader, &context->span->dropped_events_count);
}

static int unpack_span_dropped_links_count(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_uint32_tag(reader, &context->span->dropped_links_count);
}

static int unpack_span_events(mpack_reader_t *reader, size_t index, void *ctx)
{
    return ctr_mpack_unpack_array(reader, unpack_event, ctx);
}


static int unpack_span_links(mpack_reader_t *reader, size_t index, void *ctx)
{
    return ctr_mpack_unpack_array(reader, unpack_link, ctx);
}

static int unpack_span_status_code(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_int32_tag(reader, &context->span->status.code);
}

static int unpack_span_status_message(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->span->status.message);
}

static int unpack_span_status(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"code",    unpack_span_status_code},
            {"message", unpack_span_status_message},
            {NULL,      NULL}
        };

    return ctr_mpack_unpack_map(reader, callbacks, ctx);
}

static int unpack_span_schema_url(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->span->schema_url);
}

static int unpack_span(mpack_reader_t *reader, size_t index, void *ctx)
{
    int result;
    struct ctr_msgpack_decode_context    *context = ctx;
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"trace_id",                 unpack_span_trace_id},
            {"span_id",                  unpack_span_span_id},
            {"parent_span_id",           unpack_span_parent_span_id},
            {"trace_state",              unpack_span_trace_state},
            {"name",                     unpack_span_name},
            {"kind",                     unpack_span_kind},
            {"start_time_unix_nano",     unpack_span_start_time_unix_nano},
            {"end_time_unix_nano",       unpack_span_end_time_unix_nano},
            {"attributes",               unpack_span_attributes},
            {"dropped_attributes_count", unpack_span_dropped_attributes_count},
            {"dropped_events_count",     unpack_span_dropped_events_count},
            {"dropped_links_count",      unpack_span_dropped_links_count},
            {"events",                   unpack_span_events},
            {"links",                    unpack_span_links},
            {"status",                   unpack_span_status},
            {"schema_url",               unpack_span_schema_url},
            {NULL,                       NULL}
        };

    context->span = ctr_span_create(context->trace, context->scope_span, "", NULL);

    if (context->span == NULL) {
        return CTR_DECODE_MSGPACK_ALLOCATION_ERROR;
    }
    result = ctr_mpack_unpack_map(reader, callbacks, ctx);

    if (result != CTR_DECODE_MSGPACK_SUCCESS) {
        ctr_span_destroy(context->span);
        context->span = NULL;
    }

    return result;
}

/* Scope span callbacks */

static int unpack_scope_span_spans(mpack_reader_t *reader, size_t index, void *ctx)
{
    return ctr_mpack_unpack_array(reader, unpack_span, ctx);
}

static int unpack_scope_span_schema_url(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    if (context->scope_span->schema_url != NULL) {
        cfl_sds_destroy(context->scope_span->schema_url);

        context->scope_span->schema_url = NULL;
    }

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->scope_span->schema_url);
}

static int unpack_scope_span(mpack_reader_t *reader, size_t index, void *ctx)
{
    int result;
    struct ctr_msgpack_decode_context    *context = ctx;
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"scope",      unpack_scope_span_instrumentation_scope},
            {"spans",      unpack_scope_span_spans},
            {"schema_url", unpack_scope_span_schema_url},
            {NULL,         NULL}
        };

    context->scope_span = ctr_scope_span_create(context->resource_span);

    if (context->scope_span == NULL) {
        return CTR_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = ctr_mpack_unpack_map(reader, callbacks, ctx);
    if (result != CTR_DECODE_MSGPACK_SUCCESS) {
	ctr_scope_span_destroy(context->scope_span);
	context->scope_span = NULL;
    }
    return result;
}

/* Resource span callbacks */

static int unpack_resource_span_scope_spans(mpack_reader_t *reader, size_t index, void *ctx)
{
    return ctr_mpack_unpack_array(reader, unpack_scope_span, ctx);
}

static int unpack_resource_span_schema_url(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context *context = ctx;

    if (context->resource_span->schema_url != NULL) {
        cfl_sds_destroy(context->resource_span->schema_url);

        context->resource_span->schema_url = NULL;
    }

    return ctr_mpack_consume_string_or_nil_tag(reader, &context->resource_span->schema_url);
}

static int unpack_resource_span(mpack_reader_t *reader, size_t index, void *ctx)
{
    struct ctr_msgpack_decode_context    *context = ctx;
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"resource",    unpack_resource},
            {"schema_url",  unpack_resource_span_schema_url},
            {"scope_spans", unpack_resource_span_scope_spans},
            {NULL,          NULL}
        };

    context->resource_span = ctr_resource_span_create(context->trace);

    if (context->resource_span == NULL) {
        return CTR_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    context->resource = context->resource_span->resource;

    return ctr_mpack_unpack_map(reader, callbacks, ctx);
}

/* Outermost block callbacks*/

static int unpack_resource_spans(mpack_reader_t *reader, size_t index, void *ctx)
{
    return ctr_mpack_unpack_array(reader, unpack_resource_span, ctx);
}

static int unpack_context(mpack_reader_t *reader, struct ctr_msgpack_decode_context *ctx)
{
    struct ctr_mpack_map_entry_callback_t callbacks[] = \
        {
            {"resourceSpans", unpack_resource_spans},
            {NULL,            NULL}
        };

    return ctr_mpack_unpack_map(reader, callbacks, (void *) ctx);
}

int ctr_decode_msgpack_create(struct ctrace **out_context, char *in_buf, size_t in_size, size_t *offset)
{
    size_t                            remainder;
    struct ctr_msgpack_decode_context context;
    mpack_reader_t                    reader;
    int                               result;

    memset(&context, 0, sizeof(context));

    context.trace = ctr_create(NULL);

    if (context.trace == NULL) {
        return -1;
    }

    in_size -= *offset;

    mpack_reader_init_data(&reader, &in_buf[*offset], in_size);

    result = unpack_context(&reader, &context);

    remainder = mpack_reader_remaining(&reader, NULL);

    *offset += in_size - remainder;

    mpack_reader_destroy(&reader);

    if (result != CTR_DECODE_MSGPACK_SUCCESS) {
        ctr_destroy(context.trace);

        context.trace = NULL;
    }

    *out_context = context.trace;

    return result;
}

void ctr_decode_msgpack_destroy(struct ctrace *context)
{
    if (context != NULL) {
        ctr_destroy(context);
    }
}
