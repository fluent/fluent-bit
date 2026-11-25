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

/* Browser SDK inspection of routing decisions. Reports only; see the header. */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_mp_chunk.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_router.h>
#include <fluent-bit/flb_event.h>
#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/wasm/flb_wasm_inspect.h>

#include <msgpack.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* A trace is a diagnostic for a handful of sample records, not a log. */
#define TRACE_LIMIT_BYTES  (512 * 1024)
#define TRACE_LIMIT_EVENTS 20000

int flb_wasm_trace_active = FLB_FALSE;

static pthread_mutex_t trace_mutex = PTHREAD_MUTEX_INITIALIZER;
static msgpack_sbuffer trace_buffer;
static int trace_initialized;
static size_t trace_events;
static size_t trace_dropped;
static size_t trace_append_id;
static size_t trace_event_start;

static void pack_str(msgpack_packer *pk, const char *value)
{
    size_t length;

    length = strlen(value);
    msgpack_pack_str(pk, length);
    msgpack_pack_str_body(pk, value, length);
}

static void pack_str_len(msgpack_packer *pk, const char *value, size_t length)
{
    msgpack_pack_str(pk, length);
    msgpack_pack_str_body(pk, value, length);
}

static void pack_bool(msgpack_packer *pk, int value)
{
    if (value) {
        msgpack_pack_true(pk);
    }
    else {
        msgpack_pack_false(pk);
    }
}

/* Hand a msgpack document to the caller as JSON in a malloc(3) buffer. */
static int result_from_msgpack(msgpack_sbuffer *sbuf, char **out, size_t *out_size)
{
    flb_sds_t json;
    size_t length;
    char *copy;

    json = flb_msgpack_raw_to_json_sds(sbuf->data, sbuf->size, FLB_TRUE);
    if (!json) {
        return -1;
    }
    length = flb_sds_len(json);
    copy = malloc(length + 1);
    if (!copy) {
        flb_sds_destroy(json);
        return -1;
    }
    memcpy(copy, json, length);
    copy[length] = '\0';
    flb_sds_destroy(json);
    *out = copy;
    *out_size = length;

    return 0;
}

static int result_error(const char *reason, char **out, size_t *out_size)
{
    int ret;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pk, 1);
    pack_str(&pk, "error");
    pack_str(&pk, reason);
    ret = result_from_msgpack(&sbuf, out, out_size);
    msgpack_sbuffer_destroy(&sbuf);

    return ret;
}

static msgpack_object *map_get(msgpack_object *map, const char *key)
{
    uint32_t index;
    size_t length;
    msgpack_object *name;

    if (map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }
    length = strlen(key);
    for (index = 0; index < map->via.map.size; index++) {
        name = &map->via.map.ptr[index].key;
        if (name->type == MSGPACK_OBJECT_STR && name->via.str.size == length &&
            memcmp(name->via.str.ptr, key, length) == 0) {
            return &map->via.map.ptr[index].val;
        }
    }

    return NULL;
}

/*
 * The route parser reads variants that own their strings, as the configuration
 * loader builds them; flb_mp_object_to_cfl() only references the source buffer.
 */
static struct cfl_variant *variant_from_msgpack(msgpack_object *object)
{
    uint32_t index;
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *child;
    struct cfl_variant *variant;
    msgpack_object_kv *pair;

    switch (object->type) {
    case MSGPACK_OBJECT_BOOLEAN:
        return cfl_variant_create_from_bool(object->via.boolean);
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        return cfl_variant_create_from_uint64(object->via.u64);
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        return cfl_variant_create_from_int64(object->via.i64);
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        return cfl_variant_create_from_double(object->via.f64);
    case MSGPACK_OBJECT_STR:
        return cfl_variant_create_from_string_s((char *) object->via.str.ptr,
                                                object->via.str.size, CFL_FALSE);
    case MSGPACK_OBJECT_ARRAY:
        array = cfl_array_create(object->via.array.size);
        if (!array) {
            return NULL;
        }
        for (index = 0; index < object->via.array.size; index++) {
            child = variant_from_msgpack(&object->via.array.ptr[index]);
            if (!child || cfl_array_append(array, child) != 0) {
                if (child) {
                    cfl_variant_destroy(child);
                }
                cfl_array_destroy(array);
                return NULL;
            }
        }
        variant = cfl_variant_create_from_array(array);
        if (!variant) {
            cfl_array_destroy(array);
        }
        return variant;
    case MSGPACK_OBJECT_MAP:
        kvlist = cfl_kvlist_create();
        if (!kvlist) {
            return NULL;
        }
        for (index = 0; index < object->via.map.size; index++) {
            pair = &object->via.map.ptr[index];
            child = pair->key.type == MSGPACK_OBJECT_STR ?
                    variant_from_msgpack(&pair->val) : NULL;
            if (!child || cfl_kvlist_insert_s(kvlist, (char *) pair->key.via.str.ptr,
                                              pair->key.via.str.size, child) != 0) {
                if (child) {
                    cfl_variant_destroy(child);
                }
                cfl_kvlist_destroy(kvlist);
                return NULL;
            }
        }
        variant = cfl_variant_create_from_kvlist(kvlist);
        if (!variant) {
            cfl_kvlist_destroy(kvlist);
        }
        return variant;
    default:
        break;
    }

    return NULL;
}

/* Encode the samples as log events, the form the router sees after an input. */
static int encode_samples(struct flb_log_event_encoder *encoder,
                          msgpack_object *records, msgpack_object *metadata)
{
    uint32_t index;
    int ret;
    msgpack_object *record;
    msgpack_object *meta;

    for (index = 0; index < records->via.array.size; index++) {
        record = &records->via.array.ptr[index];
        if (record->type != MSGPACK_OBJECT_MAP) {
            return -1;
        }
        ret = flb_log_event_encoder_begin_record(encoder);
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_current_timestamp(encoder);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS && metadata != NULL) {
            meta = &metadata->via.array.ptr[index];
            if (meta->type == MSGPACK_OBJECT_MAP) {
                ret = flb_log_event_encoder_set_metadata_from_msgpack_object(encoder, meta);
            }
            else if (meta->type != MSGPACK_OBJECT_NIL) {
                return -1;
            }
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_set_body_from_msgpack_object(encoder, record);
        }
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            ret = flb_log_event_encoder_commit_record(encoder);
        }
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            return -1;
        }
    }

    return 0;
}

int flb_wasm_inspect_condition(const char *json, size_t size,
                               char **out, size_t *out_size)
{
    int root_type;
    int result = -1;
    int context_ready = FLB_FALSE;
    int32_t record_type;
    char *mp_buf = NULL;
    size_t mp_size = 0;
    size_t offset = 0;
    const char *reason = NULL;
    msgpack_unpacked unpacked;
    msgpack_object *condition_obj;
    msgpack_object *records;
    msgpack_object *metadata;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;
    struct cfl_variant *condition_variant = NULL;
    struct flb_route_condition *condition = NULL;
    struct flb_route route;
    struct flb_log_event_encoder *encoder = NULL;
    struct flb_event_chunk *chunk = NULL;
    struct flb_router_chunk_context context;
    struct flb_mp_chunk_record *record;
    struct cfl_list *head;

    if (!json || size == 0 || !out || !out_size) {
        return -1;
    }
    *out = NULL;
    *out_size = 0;

    if (flb_pack_json(json, size, &mp_buf, &mp_size, &root_type, NULL) != 0) {
        return result_error("the request is not valid JSON", out, out_size);
    }
    msgpack_unpacked_init(&unpacked);
    if (msgpack_unpack_next(&unpacked, mp_buf, mp_size, &offset) != MSGPACK_UNPACK_SUCCESS ||
        unpacked.data.type != MSGPACK_OBJECT_MAP) {
        reason = "the request must be a JSON object";
        goto done;
    }

    condition_obj = map_get(&unpacked.data, "condition");
    records = map_get(&unpacked.data, "records");
    metadata = map_get(&unpacked.data, "metadata");
    if (!condition_obj || condition_obj->type != MSGPACK_OBJECT_MAP) {
        reason = "'condition' must be a map";
        goto done;
    }
    if (!records || records->type != MSGPACK_OBJECT_ARRAY) {
        reason = "'records' must be a list of objects";
        goto done;
    }
    if (metadata && (metadata->type != MSGPACK_OBJECT_ARRAY ||
                     metadata->via.array.size != records->via.array.size)) {
        reason = "'metadata' must be a list with one entry per record";
        goto done;
    }

    condition_variant = variant_from_msgpack(condition_obj);
    if (!condition_variant) {
        reason = "'condition' holds a value a condition cannot use";
        goto done;
    }
    condition = flb_router_condition_create(condition_variant,
                                            FLB_ROUTER_SIGNAL_LOGS, &reason);
    if (!condition) {
        goto done;
    }
    memset(&route, 0, sizeof(route));
    route.signals = FLB_ROUTER_SIGNAL_LOGS;
    route.condition = condition;
    /* The engine compiles on first use and treats a failure as "no match". */
    if (!flb_router_route_get_condition(&route)) {
        reason = "a rule has an unknown 'op', or a 'value' its 'op' cannot use";
        goto done;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pk, 1);
    pack_str(&pk, "matched");
    msgpack_pack_array(&pk, records->via.array.size);

    if (records->via.array.size > 0) {
        encoder = flb_log_event_encoder_create(FLB_LOG_EVENT_FORMAT_DEFAULT);
        if (!encoder || encode_samples(encoder, records, metadata) != 0) {
            msgpack_sbuffer_destroy(&sbuf);
            reason = "every record must be a JSON object";
            goto done;
        }
        chunk = flb_event_chunk_create(FLB_EVENT_TYPE_LOGS, records->via.array.size,
                                       "inspect", 7,
                                       encoder->output_buffer, encoder->output_length);
        if (!chunk || flb_router_chunk_context_init(&context) != 0) {
            msgpack_sbuffer_destroy(&sbuf);
            goto done;
        }
        context_ready = FLB_TRUE;
        if (flb_router_chunk_context_prepare_logs(&context, chunk) != 0 ||
            !context.chunk_cobj) {
            msgpack_sbuffer_destroy(&sbuf);
            goto done;
        }
        cfl_list_foreach(head, &context.chunk_cobj->records) {
            record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
            if (flb_log_event_decoder_get_record_type(&record->event, &record_type) == 0 &&
                record_type != FLB_LOG_EVENT_NORMAL) {
                continue;
            }
            pack_bool(&pk, flb_router_condition_evaluate_record(&route, record) == FLB_TRUE);
        }
    }

    result = result_from_msgpack(&sbuf, out, out_size);
    msgpack_sbuffer_destroy(&sbuf);

done:
    if (context_ready) {
        flb_router_chunk_context_destroy(&context);
    }
    if (chunk) {
        flb_event_chunk_destroy(chunk);
    }
    if (encoder) {
        flb_log_event_encoder_destroy(encoder);
    }
    if (condition) {
        flb_router_condition_destroy(condition);
    }
    if (condition_variant) {
        cfl_variant_destroy(condition_variant);
    }
    msgpack_unpacked_destroy(&unpacked);
    flb_free(mp_buf);
    if (result != 0 && reason) {
        return result_error(reason, out, out_size);
    }

    return result;
}

static int input_index(struct flb_config *config, struct flb_input_instance *ins)
{
    int index = 0;
    struct mk_list *head;

    mk_list_foreach(head, &config->inputs) {
        if (mk_list_entry(head, struct flb_input_instance, _head) == ins) {
            return index;
        }
        index++;
    }

    return -1;
}

static int filter_index(struct flb_config *config, struct flb_filter_instance *ins)
{
    int index = 0;
    struct mk_list *head;

    mk_list_foreach(head, &config->filters) {
        if (mk_list_entry(head, struct flb_filter_instance, _head) == ins) {
            return index;
        }
        index++;
    }

    return -1;
}

static int output_index(struct flb_config *config, struct flb_output_instance *ins)
{
    int index = 0;
    struct mk_list *head;

    mk_list_foreach(head, &config->outputs) {
        if (mk_list_entry(head, struct flb_output_instance, _head) == ins) {
            return index;
        }
        index++;
    }

    return -1;
}

static void pack_instance(msgpack_packer *pk, int index, const char *name,
                          const char *plugin, const char *alias)
{
    pack_str(pk, "index");
    msgpack_pack_int(pk, index);
    pack_str(pk, "name");
    pack_str(pk, name);
    pack_str(pk, "plugin");
    pack_str(pk, plugin ? plugin : "");
    pack_str(pk, "alias");
    if (alias) {
        pack_str(pk, alias);
    }
    else {
        msgpack_pack_nil(pk);
    }
}

static const char *output_status_name(int status)
{
    switch (status) {
    case FLB_ROUTE_OUTPUT_CONNECTED:
        return "connected";
    case FLB_ROUTE_OUTPUT_ALREADY_CONNECTED:
        return "already_connected";
    case FLB_ROUTE_OUTPUT_NOT_FOUND:
        return "not_found";
    case FLB_ROUTE_OUTPUT_SIGNAL_NOT_SUPPORTED:
        return "signal_not_supported";
    case FLB_ROUTE_OUTPUT_CONNECT_FAILED:
        return "connect_failed";
    }

    return "pending";
}

static void pack_signals(msgpack_packer *pk, uint32_t signals)
{
    int count;

    count = ((signals & FLB_ROUTER_SIGNAL_LOGS) ? 1 : 0) +
            ((signals & FLB_ROUTER_SIGNAL_METRICS) ? 1 : 0) +
            ((signals & FLB_ROUTER_SIGNAL_TRACES) ? 1 : 0);
    msgpack_pack_array(pk, count);
    if (signals & FLB_ROUTER_SIGNAL_LOGS) {
        pack_str(pk, "logs");
    }
    if (signals & FLB_ROUTER_SIGNAL_METRICS) {
        pack_str(pk, "metrics");
    }
    if (signals & FLB_ROUTER_SIGNAL_TRACES) {
        pack_str(pk, "traces");
    }
}

static void pack_routes(msgpack_packer *pk, struct flb_config *config,
                        struct flb_input_instance *ins)
{
    size_t count = 0;
    struct cfl_list *input_head;
    struct cfl_list *route_head;
    struct cfl_list *output_head;
    struct flb_input_routes *input_routes;
    struct flb_route *route;
    struct flb_route_output *route_output;

    cfl_list_foreach(input_head, &config->input_routes) {
        input_routes = cfl_list_entry(input_head, struct flb_input_routes, _head);
        if (input_routes->instance == ins) {
            count += cfl_list_size(&input_routes->routes);
        }
    }

    msgpack_pack_array(pk, count);
    cfl_list_foreach(input_head, &config->input_routes) {
        input_routes = cfl_list_entry(input_head, struct flb_input_routes, _head);
        if (input_routes->instance != ins) {
            continue;
        }
        cfl_list_foreach(route_head, &input_routes->routes) {
            route = cfl_list_entry(route_head, struct flb_route, _head);

            msgpack_pack_map(pk, 7);
            pack_str(pk, "name");
            pack_str(pk, route->name ? route->name : "");
            pack_str(pk, "signals");
            pack_signals(pk, route->signals);
            pack_str(pk, "conditional");
            pack_bool(pk, route->condition != NULL);
            pack_str(pk, "isDefault");
            pack_bool(pk, route->condition != NULL && route->condition->is_default);
            pack_str(pk, "perRecord");
            pack_bool(pk, route->per_record_routing);
            /* Records are split, and tagged with the route name, only then. */
            pack_str(pk, "split");
            pack_bool(pk, route->condition != NULL || route->per_record_routing);
            pack_str(pk, "outputs");
            msgpack_pack_array(pk, cfl_list_size(&route->outputs));
            cfl_list_foreach(output_head, &route->outputs) {
                route_output = cfl_list_entry(output_head, struct flb_route_output, _head);

                msgpack_pack_map(pk, 5);
                pack_str(pk, "requested");
                pack_str(pk, route_output->name ? route_output->name : "");
                pack_str(pk, "fallback");
                if (route_output->fallback) {
                    pack_str(pk, route_output->fallback);
                }
                else {
                    msgpack_pack_nil(pk);
                }
                pack_str(pk, "resolved");
                if (route_output->ins) {
                    msgpack_pack_int(pk, output_index(config, route_output->ins));
                }
                else {
                    msgpack_pack_nil(pk);
                }
                pack_str(pk, "usedFallback");
                pack_bool(pk, route_output->used_fallback);
                pack_str(pk, "status");
                pack_str(pk, output_status_name(route_output->status));
            }
        }
    }
}

static void pack_paths(msgpack_packer *pk, struct flb_config *config,
                       struct cfl_list *paths)
{
    struct cfl_list *head;
    struct flb_router_path *path;

    msgpack_pack_array(pk, cfl_list_size(paths));
    cfl_list_foreach(head, paths) {
        path = cfl_list_entry(head, struct flb_router_path, _head);
        msgpack_pack_int(pk, output_index(config, path->ins));
    }
}

/* 'match_regex' only exists in builds with regular expression support. */
static void *filter_match_regex(struct flb_filter_instance *filter)
{
#ifdef FLB_HAVE_REGEX
    return filter->match_regex;
#else
    (void) filter;
    return NULL;
#endif
}

static void *output_match_regex(struct flb_output_instance *output)
{
#ifdef FLB_HAVE_REGEX
    return output->match_regex;
#else
    (void) output;
    return NULL;
#endif
}

static void pack_match(msgpack_packer *pk, const char *match, int has_regex)
{
    pack_str(pk, "match");
    if (match) {
        pack_str(pk, match);
    }
    else {
        msgpack_pack_nil(pk);
    }
    pack_str(pk, "matchRegex");
    pack_bool(pk, has_regex);
}

int flb_wasm_inspect_topology(struct flb_config *config,
                              char **out, size_t *out_size)
{
    int ret;
    int index;
    int matches;
    struct mk_list *head;
    struct mk_list *input_head;
    struct flb_input_instance *input;
    struct flb_filter_instance *filter;
    struct flb_output_instance *output;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;

    if (!config || !out || !out_size) {
        return -1;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pk, 3);

    pack_str(&pk, "inputs");
    msgpack_pack_array(&pk, mk_list_size(&config->inputs));
    index = 0;
    mk_list_foreach(head, &config->inputs) {
        input = mk_list_entry(head, struct flb_input_instance, _head);

        msgpack_pack_map(&pk, 8);
        pack_instance(&pk, index++, input->name, input->p ? input->p->name : NULL,
                      input->alias);
        pack_str(&pk, "tag");
        if (input->tag) {
            pack_str_len(&pk, input->tag, input->tag_len);
        }
        else {
            msgpack_pack_nil(&pk);
        }
        /* Outputs whose 'match' selected this input's configured tag. */
        pack_str(&pk, "matchedOutputs");
        pack_paths(&pk, config, &input->routes);
        /* Outputs connected by the input's routes; these replace tag matching. */
        pack_str(&pk, "directOutputs");
        pack_paths(&pk, config, &input->routes_direct);
        pack_str(&pk, "routes");
        pack_routes(&pk, config, input);
    }

    pack_str(&pk, "filters");
    msgpack_pack_array(&pk, mk_list_size(&config->filters));
    index = 0;
    mk_list_foreach(head, &config->filters) {
        filter = mk_list_entry(head, struct flb_filter_instance, _head);

        msgpack_pack_map(&pk, 7);
        pack_instance(&pk, index++, filter->name, filter->p ? filter->p->name : NULL,
                      filter->alias);
        pack_match(&pk, filter->match, filter_match_regex(filter) != NULL);
        /* Inputs whose configured tag this filter selects. */
        matches = 0;
        mk_list_foreach(input_head, &config->inputs) {
            input = mk_list_entry(input_head, struct flb_input_instance, _head);
            if (input->tag && flb_router_match(input->tag, input->tag_len,
                                               filter->match, filter_match_regex(filter))) {
                matches++;
            }
        }
        pack_str(&pk, "matchesInputs");
        msgpack_pack_array(&pk, matches);
        mk_list_foreach(input_head, &config->inputs) {
            input = mk_list_entry(input_head, struct flb_input_instance, _head);
            if (input->tag && flb_router_match(input->tag, input->tag_len,
                                               filter->match, filter_match_regex(filter))) {
                msgpack_pack_int(&pk, input_index(config, input));
            }
        }
    }

    pack_str(&pk, "outputs");
    msgpack_pack_array(&pk, mk_list_size(&config->outputs));
    index = 0;
    mk_list_foreach(head, &config->outputs) {
        output = mk_list_entry(head, struct flb_output_instance, _head);

        msgpack_pack_map(&pk, 6);
        pack_instance(&pk, index++, output->name, output->p ? output->p->name : NULL,
                      output->alias);
        pack_match(&pk, output->match, output_match_regex(output) != NULL);
    }

    ret = result_from_msgpack(&sbuf, out, out_size);
    msgpack_sbuffer_destroy(&sbuf);

    return ret;
}

void flb_wasm_trace_set(int enabled)
{
    pthread_mutex_lock(&trace_mutex);
    if (!trace_initialized) {
        msgpack_sbuffer_init(&trace_buffer);
        trace_initialized = FLB_TRUE;
    }
    msgpack_sbuffer_clear(&trace_buffer);
    trace_events = 0;
    trace_dropped = 0;
    trace_append_id = 0;
    flb_wasm_trace_active = enabled ? FLB_TRUE : FLB_FALSE;
    pthread_mutex_unlock(&trace_mutex);
}

int flb_wasm_trace_take(char **out, size_t *out_size)
{
    int ret;
    msgpack_sbuffer sbuf;
    msgpack_packer pk;

    if (!out || !out_size) {
        return -1;
    }

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pk, 2);

    pthread_mutex_lock(&trace_mutex);
    pack_str(&pk, "events");
    msgpack_pack_array(&pk, trace_events);
    if (trace_initialized && trace_buffer.size > 0) {
        msgpack_sbuffer_write(&sbuf, trace_buffer.data, trace_buffer.size);
        msgpack_sbuffer_clear(&trace_buffer);
    }
    pack_str(&pk, "dropped");
    msgpack_pack_uint64(&pk, trace_dropped);
    trace_events = 0;
    trace_dropped = 0;
    pthread_mutex_unlock(&trace_mutex);

    ret = result_from_msgpack(&sbuf, out, out_size);
    msgpack_sbuffer_destroy(&sbuf);

    return ret;
}

/*
 * Called with the mutex held. Returns 0 with a packer ready for the event
 * fields, or -1 when the event is dropped. A started event is closed with
 * trace_end().
 */
static int trace_begin(msgpack_packer *pk, const char *stage, int fields)
{
    if (!flb_wasm_trace_active || !trace_initialized ||
        trace_events >= TRACE_LIMIT_EVENTS || trace_buffer.size >= TRACE_LIMIT_BYTES) {
        trace_dropped++;
        return -1;
    }
    trace_event_start = trace_buffer.size;
    msgpack_packer_init(pk, &trace_buffer, msgpack_sbuffer_write);
    msgpack_pack_map(pk, fields + 1);
    pack_str(pk, "stage");
    pack_str(pk, stage);

    return 0;
}

/* Keep the event only if the whole of it fits in the byte limit. */
static void trace_end(void)
{
    if (trace_buffer.size > TRACE_LIMIT_BYTES) {
        trace_buffer.size = trace_event_start;
        trace_dropped++;
        return;
    }
    trace_events++;
}

static void trace_input(msgpack_packer *pk, struct flb_input_instance *ins)
{
    pack_str(pk, "input");
    msgpack_pack_int(pk, ins && ins->config ? input_index(ins->config, ins) : -1);
}

static void trace_tag(msgpack_packer *pk, const char *tag, size_t tag_len)
{
    pack_str(pk, "tag");
    pack_str_len(pk, tag ? tag : "", tag ? tag_len : 0);
}

void flb_wasm_trace_append(struct flb_input_instance *ins,
                           const char *tag, size_t tag_len, size_t records)
{
    msgpack_packer pk;

    pthread_mutex_lock(&trace_mutex);
    trace_append_id++;
    if (trace_begin(&pk, "append", 4) == 0) {
        pack_str(&pk, "append");
        msgpack_pack_uint64(&pk, trace_append_id);
        trace_input(&pk, ins);
        trace_tag(&pk, tag, tag_len);
        pack_str(&pk, "records");
        msgpack_pack_uint64(&pk, records);
        trace_end();
    }
    pthread_mutex_unlock(&trace_mutex);
}

void flb_wasm_trace_route(struct flb_input_instance *ins, size_t record,
                          struct flb_route *route, int is_default)
{
    msgpack_packer pk;

    pthread_mutex_lock(&trace_mutex);
    if (trace_begin(&pk, "route", 5) == 0) {
        pack_str(&pk, "append");
        msgpack_pack_uint64(&pk, trace_append_id);
        pack_str(&pk, "record");
        msgpack_pack_uint64(&pk, record);
        trace_input(&pk, ins);
        pack_str(&pk, "route");
        pack_str(&pk, route && route->name ? route->name : "");
        pack_str(&pk, "isDefault");
        pack_bool(&pk, is_default);
        trace_end();
    }
    pthread_mutex_unlock(&trace_mutex);
}

void flb_wasm_trace_unrouted(struct flb_input_instance *ins, size_t record)
{
    msgpack_packer pk;

    pthread_mutex_lock(&trace_mutex);
    if (trace_begin(&pk, "unrouted", 3) == 0) {
        pack_str(&pk, "append");
        msgpack_pack_uint64(&pk, trace_append_id);
        pack_str(&pk, "record");
        msgpack_pack_uint64(&pk, record);
        trace_input(&pk, ins);
        trace_end();
    }
    pthread_mutex_unlock(&trace_mutex);
}

void flb_wasm_trace_filter(struct flb_filter_instance *filter,
                           struct flb_input_instance *ins,
                           const char *tag, size_t tag_len,
                           size_t records_in, size_t records_out, int modified)
{
    msgpack_packer pk;

    pthread_mutex_lock(&trace_mutex);
    if (trace_begin(&pk, "filter", 6) == 0) {
        trace_input(&pk, ins);
        trace_tag(&pk, tag, tag_len);
        pack_str(&pk, "filter");
        msgpack_pack_int(&pk, filter && filter->config ?
                         filter_index(filter->config, filter) : -1);
        pack_str(&pk, "recordsIn");
        msgpack_pack_uint64(&pk, records_in);
        pack_str(&pk, "recordsOut");
        msgpack_pack_uint64(&pk, records_out);
        pack_str(&pk, "modified");
        pack_bool(&pk, modified);
        trace_end();
    }
    pthread_mutex_unlock(&trace_mutex);
}

void flb_wasm_trace_output(struct flb_output_instance *output,
                           struct flb_input_instance *ins,
                           const char *tag, size_t tag_len, size_t records)
{
    msgpack_packer pk;

    pthread_mutex_lock(&trace_mutex);
    if (trace_begin(&pk, "output", 4) == 0) {
        trace_input(&pk, ins);
        trace_tag(&pk, tag, tag_len);
        pack_str(&pk, "output");
        msgpack_pack_int(&pk, output && output->config ?
                         output_index(output->config, output) : -1);
        pack_str(&pk, "records");
        msgpack_pack_uint64(&pk, records);
        trace_end();
    }
    pthread_mutex_unlock(&trace_mutex);
}

void flb_wasm_trace_undelivered(struct flb_input_instance *ins,
                                const char *tag, size_t tag_len, size_t records)
{
    msgpack_packer pk;

    pthread_mutex_lock(&trace_mutex);
    if (trace_begin(&pk, "undelivered", 3) == 0) {
        trace_input(&pk, ins);
        trace_tag(&pk, tag, tag_len);
        pack_str(&pk, "records");
        msgpack_pack_uint64(&pk, records);
        trace_end();
    }
    pthread_mutex_unlock(&trace_mutex);
}
