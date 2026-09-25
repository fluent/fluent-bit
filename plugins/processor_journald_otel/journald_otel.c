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

/* Mapping based on the proposal in opentelemetry-specification PR #4995.
 * Variant copy helpers adapted from bachp/fluent-bit's journald-mapping branch.
 */

#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_conditionals.h>
#include <fluent-bit/flb_time.h>
#include <cfl/cfl.h>
#include <stdint.h>
#include <string.h>

struct jo_ctx {
    int lowercase;
    int strip_underscores;
};

struct jo_field {
    char *source;
    char *destination;
    int resource;
    int numeric;
};

static const struct jo_field fields[] = {
    {"_HOSTNAME", "host.name", FLB_TRUE, FLB_FALSE},
    {"_PID", "process.pid", FLB_TRUE, FLB_TRUE},
    {"_COMM", "process.executable.name", FLB_TRUE, FLB_FALSE},
    {"_EXE", "process.executable.path", FLB_TRUE, FLB_FALSE},
    {"_CMDLINE", "process.command_line", FLB_TRUE, FLB_FALSE},
    {"CODE_FILE", "code.file.path", FLB_FALSE, FLB_FALSE},
    {"CODE_FUNC", "code.function.name", FLB_FALSE, FLB_FALSE},
    {"CODE_LINE", "code.line.number", FLB_FALSE, FLB_TRUE},
    {"SYSLOG_FACILITY", "syslog.facility.code", FLB_FALSE, FLB_TRUE},
    {"SYSLOG_IDENTIFIER", "syslog.identifier", FLB_FALSE, FLB_FALSE},
    {"SYSLOG_PID", "syslog.pid", FLB_FALSE, FLB_TRUE},
    {"SYSLOG_TIMESTAMP", "syslog.timestamp", FLB_FALSE, FLB_FALSE}
};

static const int severity_numbers[] = {21, 19, 18, 17, 13, 10, 9, 5};
static char *severity_texts[] = {"emerg", "alert", "crit", "err", "warning",
                                 "notice", "info", "debug"};

static int key_matches(struct jo_ctx *ctx, const char *expected, cfl_sds_t key)
{
    size_t i;
    char ch;

    if (ctx->strip_underscores && expected[0] == '_') {
        expected++;
    }
    if (strlen(expected) != cfl_sds_len(key)) {
        return FLB_FALSE;
    }
    for (i = 0; expected[i]; i++) {
        ch = expected[i];
        if (ctx->lowercase && ch >= 'A' && ch <= 'Z') {
            ch += 'a' - 'A';
        }
        if (key[i] != ch) {
            return FLB_FALSE;
        }
    }
    return FLB_TRUE;
}

/* Accept only nonnegative decimal integers, including length-delimited strings. */
static int parse_uint(struct cfl_variant *value, uint64_t limit, uint64_t *number)
{
    size_t i;
    unsigned int digit;
    uint64_t result = 0;

    if (value->type == CFL_VARIANT_UINT) {
        result = value->data.as_uint64;
    }
    else if (value->type == CFL_VARIANT_INT && value->data.as_int64 >= 0) {
        result = value->data.as_int64;
    }
    else if (value->type == CFL_VARIANT_STRING && cfl_variant_size_get(value) > 0) {
        for (i = 0; i < cfl_variant_size_get(value); i++) {
            if (value->data.as_string[i] < '0' || value->data.as_string[i] > '9') {
                return FLB_FALSE;
            }
            digit = value->data.as_string[i] - '0';
            if (digit > limit || result > (limit - digit) / 10) {
                return FLB_FALSE;
            }
            result = result * 10 + digit;
        }
    }
    else {
        return FLB_FALSE;
    }
    if (result > limit) {
        return FLB_FALSE;
    }
    *number = result;
    return FLB_TRUE;
}

static struct cfl_variant *jo_variant_clone(struct cfl_variant *var);

static struct cfl_array *jo_array_clone(struct cfl_array *array)
{
    size_t i;
    struct cfl_array *out;
    struct cfl_variant *entry;

    out = cfl_array_create(array->entry_count > 0 ? array->entry_count : 1);
    if (!out) {
        return NULL;
    }

    for (i = 0; i < array->entry_count; i++) {
        entry = jo_variant_clone(array->entries[i]);
        if (!entry) {
            cfl_array_destroy(out);
            return NULL;
        }

        if (cfl_array_append(out, entry) != 0) {
            cfl_variant_destroy(entry);
            cfl_array_destroy(out);
            return NULL;
        }
    }

    return out;
}

static struct cfl_kvlist *jo_kvlist_clone(struct cfl_kvlist *kvlist)
{
    struct cfl_list *head;
    struct cfl_kvlist *out;
    struct cfl_kvpair *kvpair;
    struct cfl_variant *value;

    out = cfl_kvlist_create();
    if (!out) {
        return NULL;
    }

    cfl_list_foreach(head, &kvlist->list) {
        kvpair = cfl_list_entry(head, struct cfl_kvpair, _head);

        value = jo_variant_clone(kvpair->val);
        if (!value) {
            cfl_kvlist_destroy(out);
            return NULL;
        }

        if (cfl_kvlist_insert_s(out, kvpair->key, cfl_sds_len(kvpair->key),
                                value) != 0) {
            cfl_variant_destroy(value);
            cfl_kvlist_destroy(out);
            return NULL;
        }
    }

    return out;
}

/*
 * Deep copy a variant. The values we read still belong to the record body, so
 * anything moved into the attribute or resource lists has to be copied before
 * the body is cleared.
 */
static struct cfl_variant *jo_variant_clone(struct cfl_variant *var)
{
    struct cfl_array *array;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *out;

    switch (var->type) {
    case CFL_VARIANT_STRING:
        return cfl_variant_create_from_string_s(var->data.as_string,
                                                cfl_variant_size_get(var),
                                                CFL_FALSE);
    case CFL_VARIANT_BYTES:
        return cfl_variant_create_from_bytes(var->data.as_bytes,
                                             cfl_variant_size_get(var),
                                             CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool(var->data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64(var->data.as_int64);
    case CFL_VARIANT_UINT:
        return cfl_variant_create_from_uint64(var->data.as_uint64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double(var->data.as_double);
    case CFL_VARIANT_NULL:
        return cfl_variant_create_from_null();
    case CFL_VARIANT_ARRAY:
        array = jo_array_clone(var->data.as_array);
        if (!array) {
            return NULL;
        }
        out = cfl_variant_create_from_array(array);
        if (!out) {
            cfl_array_destroy(array);
        }
        return out;
    case CFL_VARIANT_KVLIST:
        kvlist = jo_kvlist_clone(var->data.as_kvlist);
        if (!kvlist) {
            return NULL;
        }
        out = cfl_variant_create_from_kvlist(kvlist);
        if (!out) {
            cfl_kvlist_destroy(kvlist);
        }
        return out;
    default:
        return NULL;
    }
}

static int insert_copy(struct cfl_kvlist *target, char *key, size_t length,
                       struct cfl_variant *value)
{
    struct cfl_variant *copy;

    copy = jo_variant_clone(value);
    if (!copy) {
        return -1;
    }
    if (cfl_kvlist_insert_s(target, key, length, copy) != 0) {
        cfl_variant_destroy(copy);
        return -1;
    }
    return 0;
}

static struct cfl_kvlist *add_map(struct cfl_kvlist *parent, char *key)
{
    struct cfl_kvlist *map;

    map = cfl_kvlist_create();
    if (!map) {
        return NULL;
    }
    if (cfl_kvlist_insert_kvlist(parent, key, map) != 0) {
        cfl_kvlist_destroy(map);
        return NULL;
    }
    return map;
}

/* Takes ownership of the map, including on failure. */
static struct cfl_object *map_object(struct cfl_kvlist *map)
{
    struct cfl_object *object;

    if (!map) {
        return NULL;
    }
    object = cfl_object_create();
    if (!object) {
        cfl_kvlist_destroy(map);
        return NULL;
    }
    if (cfl_object_set(object, CFL_OBJECT_KVLIST, map) != 0) {
        cfl_kvlist_destroy(map);
        cfl_object_destroy(object);
        return NULL;
    }
    return object;
}

/* Build a complete replacement before changing the source record. */
static int map_record(struct jo_ctx *ctx, struct flb_mp_chunk_cobj *chunk,
                      struct flb_mp_chunk_record *record)
{
    int ret;
    size_t i;
    uint64_t number;
    uint64_t timestamp;
    struct flb_time tm;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_kvlist *source;
    struct cfl_kvlist *metadata;
    struct cfl_kvlist *otlp;
    struct cfl_kvlist *attributes;
    struct cfl_kvlist *resource;
    struct cfl_kvlist *group_body;
    struct cfl_kvlist *group_meta;
    struct cfl_kvlist *body;
    struct cfl_kvlist *target;
    struct cfl_object *new_body = NULL;
    struct cfl_object *new_metadata = NULL;
    struct flb_mp_chunk_record *start = NULL;
    struct flb_mp_chunk_record *end = NULL;
    cfl_sds_t key;
    const struct jo_field *field;

    source = record->cobj_record->variant->data.as_kvlist;
    metadata = record->cobj_metadata->variant->data.as_kvlist;

    /* An existing OTLP record belongs to its current schema. */
    if (cfl_kvlist_fetch(metadata, "otlp")) {
        return 0;
    }

    start = flb_mp_chunk_record_create(NULL);
    end = flb_mp_chunk_record_create(NULL);
    if (!start || !end) {
        goto failure;
    }
    cfl_list_init(&start->_head);
    cfl_list_init(&end->_head);
    start->cobj_metadata = map_object(cfl_kvlist_create());
    start->cobj_record = map_object(cfl_kvlist_create());
    new_body = map_object(cfl_kvlist_create());
    new_metadata = map_object(jo_kvlist_clone(metadata));
    if (!start->cobj_metadata || !start->cobj_record || !new_body || !new_metadata) {
        goto failure;
    }
    group_meta = start->cobj_metadata->variant->data.as_kvlist;
    group_body = start->cobj_record->variant->data.as_kvlist;
    body = new_body->variant->data.as_kvlist;
    metadata = new_metadata->variant->data.as_kvlist;

    if (cfl_kvlist_insert_string(group_meta, "schema", "otlp") != 0 ||
        cfl_kvlist_insert_int64(group_meta, "resource_id", 0) != 0 ||
        cfl_kvlist_insert_int64(group_meta, "scope_id", 0) != 0) {
        goto failure;
    }
    resource = add_map(group_body, "resource");
    if (!resource || !add_map(group_body, "scope")) {
        goto failure;
    }
    resource = add_map(resource, "attributes");
    otlp = add_map(metadata, "otlp");
    if (!resource || !otlp) {
        goto failure;
    }
    attributes = add_map(otlp, "attributes");
    if (!attributes) {
        goto failure;
    }

    flb_time_copy(&tm, &record->event.timestamp);
    timestamp = flb_time_to_nanosec(&tm);
    cfl_list_foreach(head, &source->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        if (key_matches(ctx, "MESSAGE", pair->key)) {
            if (insert_copy(body, "message", 7, pair->val) != 0) {
                goto failure;
            }
            continue;
        }
        if (key_matches(ctx, "PRIORITY", pair->key) &&
            parse_uint(pair->val, 7, &number)) {
            if (cfl_kvlist_insert_int64(otlp, "severity_number", severity_numbers[number]) != 0 ||
                cfl_kvlist_insert_string(otlp, "severity_text", severity_texts[number]) != 0) {
                goto failure;
            }
            continue;
        }
        if (key_matches(ctx, "__REALTIME_TIMESTAMP", pair->key) &&
            parse_uint(pair->val, UINT64_MAX / 1000, &number)) {
            timestamp = number * 1000;
            flb_time_set(&tm, number / 1000000, (number % 1000000) * 1000);
            continue;
        }

        field = NULL;
        for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            if (key_matches(ctx, fields[i].source, pair->key)) {
                field = &fields[i];
                break;
            }
        }
        if (field) {
            target = field->resource ? resource : attributes;
            if (field->numeric && parse_uint(pair->val, INT64_MAX, &number)) {
                if (cfl_kvlist_insert_int64(target, field->destination, number) != 0) {
                    goto failure;
                }
                continue;
            }
            if (!field->numeric && pair->val->type == CFL_VARIANT_STRING) {
                if (insert_copy(target, field->destination, strlen(field->destination),
                                pair->val) != 0) {
                    goto failure;
                }
                continue;
            }
        }

        /* Unknown or malformed fields retain their original name and value. */
        key = cfl_sds_create_size(9 + cfl_sds_len(pair->key));
        if (!key) {
            goto failure;
        }
        cfl_sds_cat(key, "journald.", 9);
        cfl_sds_cat(key, pair->key, cfl_sds_len(pair->key));
        ret = insert_copy(attributes, key, cfl_sds_len(key), pair->val);
        cfl_sds_destroy(key);
        if (ret != 0) {
            goto failure;
        }
    }
    if (cfl_kvlist_insert_uint64(otlp, "timestamp", timestamp) != 0) {
        goto failure;
    }
    if (cfl_list_is_empty(&attributes->list)) {
        cfl_kvlist_remove(otlp, "attributes");
    }

    /* One group per record avoids attributing another process's resource to it. */
    flb_time_set(&start->event.timestamp, FLB_LOG_EVENT_GROUP_START, 0);
    flb_time_set(&end->event.timestamp, FLB_LOG_EVENT_GROUP_END, 0);
    start->modified = FLB_TRUE;
    end->modified = FLB_TRUE;
    cfl_list_add_before(&start->_head, &record->_head, &chunk->records);
    cfl_list_add_before(&end->_head, record->_head.next, &chunk->records);
    record->cobj_group_metadata = start->cobj_metadata;
    record->cobj_group_attributes = start->cobj_record;
    end->cobj_group_metadata = start->cobj_metadata;
    end->cobj_group_attributes = start->cobj_record;
    cfl_object_destroy(record->cobj_record);
    cfl_object_destroy(record->cobj_metadata);
    record->cobj_record = new_body;
    record->cobj_metadata = new_metadata;
    flb_time_copy(&record->event.timestamp, &tm);
    record->modified = FLB_TRUE;
    return 0;

failure:
    cfl_object_destroy(new_body);
    cfl_object_destroy(new_metadata);
    if (start) {
        cfl_object_destroy(start->cobj_metadata);
        cfl_object_destroy(start->cobj_record);
        flb_free(start);
    }
    flb_free(end);
    return -1;
}

static int cb_process_logs(struct flb_processor_instance *ins,
                           void *chunk_data, const char *tag, int tag_len)
{
    int ret;
    int type;
    int grouped = FLB_FALSE;
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct flb_condition *condition;
    struct flb_mp_chunk_record *record;
    struct flb_mp_chunk_cobj *chunk = chunk_data;

    /* Materialize all records so conditions cannot hide existing group markers. */
    condition = chunk->condition;
    chunk->condition = NULL;
    while ((ret = flb_mp_chunk_cobj_record_next(chunk, &record)) == FLB_MP_CHUNK_RECORD_OK) {
    }
    chunk->condition = condition;
    if (ret != FLB_MP_CHUNK_RECORD_EOF) {
        return FLB_PROCESSOR_FAILURE;
    }

    cfl_list_foreach_safe(head, tmp, &chunk->records) {
        record = cfl_list_entry(head, struct flb_mp_chunk_record, _head);
        if (flb_log_event_decoder_get_record_type(&record->event, &type) != 0) {
            return FLB_PROCESSOR_FAILURE;
        }
        if (type == FLB_LOG_EVENT_GROUP_START) {
            grouped = FLB_TRUE;
            continue;
        }
        if (type == FLB_LOG_EVENT_GROUP_END) {
            grouped = FLB_FALSE;
            continue;
        }
        if (grouped || record->cobj_group_metadata ||
            record->cobj_group_attributes) {
            continue;
        }
        if (condition && !flb_condition_evaluate(condition, record)) {
            continue;
        }
        if (!record->cobj_record || !record->cobj_record->variant ||
            record->cobj_record->variant->type != CFL_VARIANT_KVLIST ||
            !record->cobj_metadata || !record->cobj_metadata->variant ||
            record->cobj_metadata->variant->type != CFL_VARIANT_KVLIST) {
            continue;
        }
        if (map_record(ins->context, chunk, record) != 0) {
            flb_plg_error(ins, "could not map journald record");
            return FLB_PROCESSOR_FAILURE;
        }
    }
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_init(struct flb_processor_instance *ins, void *source_plugin_instance,
                   int source_plugin_type, struct flb_config *config)
{
    struct jo_ctx *ctx;

    ctx = flb_calloc(1, sizeof(struct jo_ctx));
    if (!ctx) {
        return FLB_PROCESSOR_FAILURE;
    }
    if (flb_processor_instance_config_map_set(ins, ctx) != 0) {
        flb_free(ctx);
        return FLB_PROCESSOR_FAILURE;
    }
    ins->context = ctx;
    return FLB_PROCESSOR_SUCCESS;
}

static int cb_exit(struct flb_processor_instance *ins, void *data)
{
    flb_free(data);
    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_BOOL, "lowercase", "false",
        0, FLB_TRUE, offsetof(struct jo_ctx, lowercase),
        "Match the lowercase setting of the systemd input."
    },
    {
        FLB_CONFIG_MAP_BOOL, "strip_underscores", "false",
        0, FLB_TRUE, offsetof(struct jo_ctx, strip_underscores),
        "Match the strip_underscores setting of the systemd input."
    },
    {0}
};

struct flb_processor_plugin processor_journald_otel_plugin = {
    .name = "journald_otel",
    .description = "Map journal fields to the OpenTelemetry Logs schema",
    .cb_init = cb_init,
    .cb_process_logs = cb_process_logs,
    .cb_exit = cb_exit,
    .config_map = config_map,
    .flags = 0
};
