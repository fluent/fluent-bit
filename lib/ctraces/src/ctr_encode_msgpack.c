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

/* local declarations */
static void pack_variant(mpack_writer_t *writer, struct cfl_variant *variant);

static void pack_bool(mpack_writer_t *writer, int b)
{
    if (b) {
        mpack_write_true(writer);
    }
    else {
        mpack_write_false(writer);
    }
}

static void pack_string(mpack_writer_t *writer, cfl_sds_t str)
{
    mpack_write_str(writer, str, cfl_sds_len(str));
}

static void pack_int64(mpack_writer_t *writer, int64_t val)
{
    mpack_write_i64(writer, val);
}

static void pack_double(mpack_writer_t *writer, double val)
{
    mpack_write_double(writer, val);
}

static void pack_array(mpack_writer_t *writer, struct cfl_array *array)
{
    int i;
    struct cfl_variant *entry;

    mpack_start_array(writer, array->entry_count);

    for (i = 0; i < array->entry_count; i++) {
        entry = array->entries[i];
        pack_variant(writer, entry);
    }
    mpack_finish_array(writer);
}

static void pack_kvlist(mpack_writer_t *writer, struct cfl_kvlist *kvlist)
{
    int count;
    struct cfl_list *head;
    struct cfl_list *list;
    struct cfl_kvpair *kvpair;

    list = &kvlist->list;
    count = cfl_list_size(list);

    mpack_start_map(writer, count);

    cfl_list_foreach(head, list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        /* key */
        mpack_write_str(writer, kvpair->key, cfl_sds_len(kvpair->key));

        /* value */
        pack_variant(writer, kvpair->val);
    }
    mpack_finish_map(writer);
}

static void pack_bytes(mpack_writer_t *writer, cfl_sds_t bytes)
{
    size_t len;

    len = cfl_sds_len(bytes);

    // mpack_start_bin(writer, len);
    mpack_write_bin(writer, bytes, len);
    // mpack_finish_bin(writer);
}

static void pack_variant(mpack_writer_t *writer, struct cfl_variant *variant)
{
    int type = variant->type;

    if (type == CFL_VARIANT_STRING) {
        pack_string(writer, variant->data.as_string);
    }
    else if (type == CFL_VARIANT_BOOL) {
        pack_bool(writer, variant->data.as_bool);
    }
    else if (type == CFL_VARIANT_INT) {
        pack_int64(writer, variant->data.as_int64);
    }
    else if (type == CFL_VARIANT_DOUBLE) {
        pack_double(writer, variant->data.as_double);
    }
    else if (type == CFL_VARIANT_ARRAY) {
        pack_array(writer, variant->data.as_array);
    }
    else if (type == CFL_VARIANT_KVLIST) {
        pack_kvlist(writer, variant->data.as_kvlist);
    }
    else if (type == CFL_VARIANT_BYTES) {
        pack_bytes(writer, variant->data.as_bytes);
    }
    else if (type == CFL_VARIANT_REFERENCE) {
        /* unsupported */
    }
}

static void pack_attributes(mpack_writer_t *writer, struct ctrace_attributes *attr)
{
    struct cfl_kvlist *kvlist;

    kvlist = attr->kv;
    pack_kvlist(writer, kvlist);
}

static void pack_instrumentation_scope(mpack_writer_t *writer, struct ctrace_instrumentation_scope *ins_scope)
{
    if (ins_scope == NULL) {
        mpack_write_nil(writer);

        return;
    }

    mpack_start_map(writer, 4);

    /* name */
    mpack_write_cstr(writer, "name");
    if (ins_scope->name) {
        mpack_write_str(writer, ins_scope->name, cfl_sds_len(ins_scope->name));
    }
    else {
        mpack_write_nil(writer);
    }

    /* version */
    mpack_write_cstr(writer, "version");
    if (ins_scope->version) {
        mpack_write_str(writer, ins_scope->version, cfl_sds_len(ins_scope->version));
    }
    else {
        mpack_write_nil(writer);
    }

    /* attributes */
    mpack_write_cstr(writer, "attributes");
    if (ins_scope->attr) {
        pack_attributes(writer, ins_scope->attr);
    }
    else {
        mpack_write_nil(writer);
    }

    /* dropped_attributes_count */
    mpack_write_cstr(writer, "dropped_attributes_count");
    mpack_write_u32(writer, ins_scope->dropped_attr_count);

    /* finish */
    mpack_finish_map(writer);
}

static void pack_id(mpack_writer_t *writer, struct ctrace_id *id)
{
    cfl_sds_t encoded_id;


    if (id) {
        encoded_id = ctr_id_to_lower_base16(id);

        if (encoded_id != NULL) {
            mpack_write_cstr(writer, encoded_id);

            cfl_sds_destroy(encoded_id);
        }
        else {
            /* we should be able to report this but at the moment
             * we are not.
             */

            mpack_write_nil(writer);
        }
    }
    else {
        mpack_write_nil(writer);
    }
}

static void pack_events(mpack_writer_t *writer, struct cfl_list *events)
{
    int count;
    struct cfl_list *head;
    struct ctrace_span_event *event;

    count = cfl_list_size(events);
    mpack_start_array(writer, count);

    cfl_list_foreach(head, events) {
        event = cfl_list_entry(head, struct ctrace_span_event, _head);

        /* start event map */
        mpack_start_map(writer, 4);

        /* time_unix_nano */
        mpack_write_cstr(writer, "time_unix_nano");
        mpack_write_u64(writer, event->time_unix_nano);

        /* name */
        mpack_write_cstr(writer, "name");
        if (event->name) {
            mpack_write_str(writer, event->name, cfl_sds_len(event->name));
        }
        else {
            mpack_write_nil(writer);
        }

        /* attributes */
        mpack_write_cstr(writer, "attributes");
        if (event->attr) {
            pack_attributes(writer, event->attr);
        }
        else {
            mpack_write_nil(writer);
        }

        /* dropped_attributes_count */
        mpack_write_cstr(writer, "dropped_attributes_count");
        mpack_write_u32(writer, event->dropped_attr_count);

        /* finish event map */
        mpack_finish_map(writer);
    }

    mpack_finish_array(writer);
}

static void pack_links(mpack_writer_t *writer, struct cfl_list *links)
{
    int count;
    struct cfl_list *head;
    struct ctrace_link *link;

    count = cfl_list_size(links);
    mpack_start_array(writer, count);

    cfl_list_foreach(head, links) {
        link = cfl_list_entry(head, struct ctrace_link, _head);

        /* start map */
        mpack_start_map(writer, 5);

        /* trace_id */
        mpack_write_cstr(writer, "trace_id");
        pack_id(writer, link->trace_id);

        /* span_id */
        mpack_write_cstr(writer, "span_id");
        pack_id(writer, link->span_id);

        /* trace_state */
        mpack_write_cstr(writer, "trace_state");
        if (link->trace_state) {
            mpack_write_str(writer, link->trace_state, cfl_sds_len(link->trace_state));
        }
        else {
            mpack_write_nil(writer);
        }

        /* attributes */
        mpack_write_cstr(writer, "attributes");
        if (link->attr) {
            pack_attributes(writer, link->attr);
        }
        else {
            mpack_write_nil(writer);
        }

        /* dropped_attributes_count */
        mpack_write_cstr(writer, "dropped_attributes_count");
        mpack_write_u32(writer, link->dropped_attr_count);

        /* end map */
        mpack_finish_map(writer);
    }

    mpack_finish_array(writer);
}

static void pack_span(mpack_writer_t *writer, struct ctrace_span *span)
{
    mpack_start_map(writer, 16);

    /* trace_id */
    mpack_write_cstr(writer, "trace_id");
    pack_id(writer, span->trace_id);

    /* span_id */
    mpack_write_cstr(writer, "span_id");
    pack_id(writer, span->span_id);

    /* parent_span_id */
    mpack_write_cstr(writer, "parent_span_id");
    pack_id(writer, span->parent_span_id);

    /* trace_state */
    mpack_write_cstr(writer, "trace_state");
    if (span->trace_state) {
        mpack_write_str(writer, span->trace_state, cfl_sds_len(span->trace_state));
    }
    else {
        mpack_write_nil(writer);
    }

    /* name */
    mpack_write_cstr(writer, "name");
    if (span->name) {
        mpack_write_str(writer, span->name, cfl_sds_len(span->name));
    }
    else {
        mpack_write_nil(writer);
    }

    /* kind */
    mpack_write_cstr(writer, "kind");
    mpack_write_u32(writer, span->kind);

    /* start_time_unix_nano */
    mpack_write_cstr(writer, "start_time_unix_nano");
    mpack_write_u64(writer, span->start_time_unix_nano);

    /* end_time_unix_nano */
    mpack_write_cstr(writer, "end_time_unix_nano");
    mpack_write_u64(writer, span->end_time_unix_nano);

    /* attributes */
    mpack_write_cstr(writer, "attributes");
    if (span->attr) {
        pack_attributes(writer, span->attr);
    }
    else {
        mpack_write_nil(writer);
    }

    /* dropped_attributes_count */
    mpack_write_cstr(writer, "dropped_attributes_count");
    mpack_write_u32(writer, span->dropped_attr_count);

    /* dropped_events_count */
    mpack_write_cstr(writer, "dropped_events_count");
    mpack_write_u32(writer, span->dropped_events_count);

    /* dropped_links_count */
    mpack_write_cstr(writer, "dropped_links_count");
    mpack_write_u32(writer, span->dropped_links_count);

    /* events */
    mpack_write_cstr(writer, "events");
    pack_events(writer, &span->events);

    /* links */
    mpack_write_cstr(writer, "links");
    pack_links(writer, &span->links);

    /* schema_url */
    mpack_write_cstr(writer, "schema_url");
    if (span->schema_url) {
        mpack_write_str(writer, span->schema_url, cfl_sds_len(span->schema_url));
    }
    else {
        mpack_write_nil(writer);
    }

    /* span_status */
    mpack_write_cstr(writer, "status");
    mpack_start_map(writer, 2);
    mpack_write_cstr(writer, "code");
    mpack_write_i32(writer, span->status.code);
    mpack_write_cstr(writer, "message");
    if (span->status.message) {
        mpack_write_str(writer, span->status.message, cfl_sds_len(span->status.message));
    }
    else {
        mpack_write_nil(writer);
    }
    mpack_finish_map(writer);

    mpack_finish_map(writer);
}

static void pack_spans(mpack_writer_t *writer, struct cfl_list *spans)
{
    int count;
    struct cfl_list *head;
    struct ctrace_span *span;

    count = cfl_list_size(spans);
    mpack_start_array(writer, count);

     cfl_list_foreach(head, spans) {
        span = cfl_list_entry(head, struct ctrace_span, _head);
        pack_span(writer, span);
    }

    mpack_finish_array(writer);
}

static void pack_scope_spans(mpack_writer_t *writer, struct cfl_list *scope_spans)
{
    int count;
    struct cfl_list *head;
    struct ctrace_scope_span *scope_span;

    count = cfl_list_size(scope_spans);

    mpack_write_cstr(writer, "scope_spans");
    mpack_start_array(writer, count);

    cfl_list_foreach(head, scope_spans) {
        scope_span = cfl_list_entry(head, struct ctrace_scope_span, _head);

        mpack_start_map(writer, 3);

        /* scope */
        mpack_write_cstr(writer, "scope");
        if (scope_span->instrumentation_scope != NULL) {
            pack_instrumentation_scope(writer, scope_span->instrumentation_scope);
        }
        else {
            mpack_write_nil(writer);
        }

        /* spans */
        mpack_write_cstr(writer, "spans");
        pack_spans(writer, &scope_span->spans);

        /* schema_url */
        mpack_write_cstr(writer, "schema_url");
        if (scope_span->schema_url) {
            mpack_write_str(writer, scope_span->schema_url, cfl_sds_len(scope_span->schema_url));
        }
        else {
            mpack_write_nil(writer);
        }

        mpack_finish_map(writer);
    }

    mpack_finish_array(writer);
}

int ctr_encode_msgpack_create(struct ctrace *ctx,  char **out_buf, size_t *out_size)
{
    int count;
    char *data;
    size_t size;
    mpack_writer_t writer;
    struct cfl_list *head;
    struct ctrace_resource_span *resource_span;
    struct ctrace_resource *resource;

    if (ctx == NULL) {
        return -1;
    }

    mpack_writer_init_growable(&writer, &data, &size);

    /* root map */
    mpack_start_map(&writer, 1);

    /* resourceSpan */
    mpack_write_cstr(&writer, "resourceSpans");

    /* array */
    count = cfl_list_size(&ctx->resource_spans);
    mpack_start_array(&writer, count);

    cfl_list_foreach(head, &ctx->resource_spans) {
        resource_span = cfl_list_entry(head, struct ctrace_resource_span, _head);

        /* resourceSpans is an array of maps, each maps containers a 'resource', 'schema_url' and 'scopeSpans' entry */
        mpack_start_map(&writer, 3);

        /* resource key */
        resource = resource_span->resource;
        mpack_write_cstr(&writer, "resource");

        /* resource val */
        mpack_start_map(&writer, 2);

        /* resource[0]: attributes */
        mpack_write_cstr(&writer, "attributes");
        if (resource->attr) {
            pack_attributes(&writer, resource->attr);
        }
        else {
            mpack_write_nil(&writer);
        }

        /* resource[1]: dropped_attributes_count */
        mpack_write_cstr(&writer, "dropped_attributes_count");
        mpack_write_u32(&writer, resource->dropped_attr_count);

        mpack_finish_map(&writer);

        /* schema_url */
        mpack_write_cstr(&writer, "schema_url");
        if (resource_span->schema_url) {
            mpack_write_str(&writer, resource_span->schema_url, cfl_sds_len(resource_span->schema_url));
        }
        else {
            mpack_write_nil(&writer);
        }

        /* scopeSpans */
        pack_scope_spans(&writer, &resource_span->scope_spans);

        mpack_finish_map(&writer); /* !resourceSpans map value */
    }

    mpack_finish_array(&writer);
    mpack_finish_map(&writer);

    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return -1;
    }

    *out_buf = data;
    *out_size = size;

    return 0;
}

void ctr_encode_msgpack_destroy(char *buf)
{
    free(buf);
}
