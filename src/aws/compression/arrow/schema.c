/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

/* Schema-directed conversion of Fluent Bit log events to Arrow arrays. */
#include <arrow-glib/arrow-glib.h>
#include <fluent-bit/aws/flb_aws_compress.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_log.h>
#include <float.h>
#include <math.h>
#include "schema.h"

struct flb_arrow_schema {
    GArrowSchema *schema;
};

static int string_equal(const msgpack_object *value, const char *text)
{
    return value != NULL && value->type == MSGPACK_OBJECT_STR &&
           value->via.str.size == strlen(text) &&
           memcmp(value->via.str.ptr, text, value->via.str.size) == 0;
}

static const msgpack_object *member(const msgpack_object *map, const char *name)
{
    uint32_t i;

    if (map == NULL || map->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }
    for (i = 0; i < map->via.map.size; i++) {
        if (string_equal(&map->via.map.ptr[i].key, name)) {
            return &map->via.map.ptr[i].val;
        }
    }
    return NULL;
}

/* Reject duplicate/unknown schema keys rather than silently changing meaning. */
static int keys_valid(const msgpack_object *map, const char **allowed, size_t count)
{
    uint32_t i;
    uint32_t j;
    size_t k;
    const msgpack_object *key;

    if (map == NULL || map->type != MSGPACK_OBJECT_MAP) {
        return FLB_FALSE;
    }
    for (i = 0; i < map->via.map.size; i++) {
        key = &map->via.map.ptr[i].key;
        for (k = 0; k < count; k++) {
            if (string_equal(key, allowed[k])) {
                break;
            }
        }
        if (k == count) {
            return FLB_FALSE;
        }
        for (j = 0; j < i; j++) {
            if (map->via.map.ptr[j].key.via.str.size == key->via.str.size &&
                memcmp(map->via.map.ptr[j].key.via.str.ptr,
                       key->via.str.ptr, key->via.str.size) == 0) {
                return FLB_FALSE;
            }
        }
    }
    return FLB_TRUE;
}

static GArrowDataType *parse_type(const msgpack_object *type)
{
    const msgpack_object *name;
    const msgpack_object *width;
    const msgpack_object *sign;
    const msgpack_object *precision;
    const char *simple_keys[] = {"name"};
    const char *int_keys[] = {"name", "bitWidth", "isSigned"};
    const char *float_keys[] = {"name", "precision"};

    name = member(type, "name");
    if (string_equal(name, "int") && keys_valid(type, int_keys, 3)) {
        width = member(type, "bitWidth");
        sign = member(type, "isSigned");
        if (width == NULL || width->type != MSGPACK_OBJECT_POSITIVE_INTEGER ||
            sign == NULL || sign->type != MSGPACK_OBJECT_BOOLEAN) {
            return NULL;
        }
        switch (width->via.u64) {
        case 8:
            return sign->via.boolean ? GARROW_DATA_TYPE(garrow_int8_data_type_new()) :
                                       GARROW_DATA_TYPE(garrow_uint8_data_type_new());
        case 16:
            return sign->via.boolean ? GARROW_DATA_TYPE(garrow_int16_data_type_new()) :
                                       GARROW_DATA_TYPE(garrow_uint16_data_type_new());
        case 32:
            return sign->via.boolean ? GARROW_DATA_TYPE(garrow_int32_data_type_new()) :
                                       GARROW_DATA_TYPE(garrow_uint32_data_type_new());
        case 64:
            return sign->via.boolean ? GARROW_DATA_TYPE(garrow_int64_data_type_new()) :
                                       GARROW_DATA_TYPE(garrow_uint64_data_type_new());
        default:
            return NULL;
        }
    }
    if (string_equal(name, "floatingpoint") && keys_valid(type, float_keys, 2)) {
        precision = member(type, "precision");
        if (string_equal(precision, "SINGLE")) {
            return GARROW_DATA_TYPE(garrow_float_data_type_new());
        }
        if (string_equal(precision, "DOUBLE")) {
            return GARROW_DATA_TYPE(garrow_double_data_type_new());
        }
        return NULL;
    }
    if (!keys_valid(type, simple_keys, 1)) {
        return NULL;
    }
    if (string_equal(name, "utf8")) {
        return GARROW_DATA_TYPE(garrow_string_data_type_new());
    }
    if (string_equal(name, "bool")) {
        return GARROW_DATA_TYPE(garrow_boolean_data_type_new());
    }
    return NULL;
}

void flb_arrow_schema_destroy(struct flb_arrow_schema *schema)
{
    if (schema != NULL) {
        g_clear_object(&schema->schema);
        flb_free(schema);
    }
}

struct flb_arrow_schema *flb_arrow_schema_create(const char *json, size_t size)
{
    struct flb_arrow_schema *result = NULL;
    msgpack_unpacked unpacked;
    char *packed = NULL;
    size_t packed_size;
    size_t consumed = 0;
    size_t offset = 0;
    int root_type;
    uint32_t i;
    const msgpack_object *fields;
    const msgpack_object *field;
    const msgpack_object *name;
    const msgpack_object *nullable;
    const msgpack_object *children;
    GArrowDataType *type;
    GArrowField *arrow_field;
    GList *list = NULL;
    GList *entry;
    char *field_name;
    const char *schema_keys[] = {"fields", "metadata"};
    const char *field_keys[] = {"name", "type", "nullable", "children", "metadata"};

    msgpack_unpacked_init(&unpacked);
    if (flb_pack_json(json, size, &packed, &packed_size, &root_type, &consumed) != 0) {
        goto done;
    }
    while (consumed < size && g_ascii_isspace(json[consumed])) {
        consumed++;
    }
    if (consumed != size ||
        msgpack_unpack_next(&unpacked, packed, packed_size, &offset) != MSGPACK_UNPACK_SUCCESS ||
        offset != packed_size || !keys_valid(&unpacked.data, schema_keys, 2)) {
        goto done;
    }
    fields = member(&unpacked.data, "fields");
    if (fields == NULL || fields->type != MSGPACK_OBJECT_ARRAY || fields->via.array.size == 0) {
        goto done;
    }
    for (i = 0; i < fields->via.array.size; i++) {
        field = &fields->via.array.ptr[i];
        if (!keys_valid(field, field_keys, 5)) {
            goto done;
        }
        name = member(field, "name");
        nullable = member(field, "nullable");
        children = member(field, "children");
        if (name == NULL || name->type != MSGPACK_OBJECT_STR || name->via.str.size == 0 ||
            memchr(name->via.str.ptr, '\0', name->via.str.size) != NULL ||
            !g_utf8_validate(name->via.str.ptr, name->via.str.size, NULL) ||
            nullable == NULL || nullable->type != MSGPACK_OBJECT_BOOLEAN ||
            (children != NULL && (children->type != MSGPACK_OBJECT_ARRAY ||
                                  children->via.array.size != 0))) {
            goto done;
        }
        for (entry = list; entry != NULL; entry = entry->next) {
            if (string_equal(name, garrow_field_get_name(entry->data))) {
                goto done;
            }
        }
        type = parse_type(member(field, "type"));
        if (type == NULL) {
            goto done;
        }
        field_name = g_strndup(name->via.str.ptr, name->via.str.size);
        arrow_field = garrow_field_new_full(field_name, type, nullable->via.boolean);
        g_free(field_name);
        g_object_unref(type);
        list = g_list_append(list, arrow_field);
    }
    result = flb_calloc(1, sizeof(*result));
    if (result != NULL) {
        result->schema = garrow_schema_new(list);
    }
done:
    if (result == NULL) {
        flb_error("[aws][arrow] invalid or unsupported Arrow JSON schema");
    }
    g_list_free_full(list, g_object_unref);
    msgpack_unpacked_destroy(&unpacked);
    flb_free(packed);
    return result;
}

static GArrowArrayBuilder *new_builder(GArrowType type)
{
    switch (type) {
    case GARROW_TYPE_BOOLEAN:
        return GARROW_ARRAY_BUILDER(garrow_boolean_array_builder_new());
    case GARROW_TYPE_STRING:
        return GARROW_ARRAY_BUILDER(garrow_string_array_builder_new());
    case GARROW_TYPE_INT8:
        return GARROW_ARRAY_BUILDER(garrow_int8_array_builder_new());
    case GARROW_TYPE_UINT8:
        return GARROW_ARRAY_BUILDER(garrow_uint8_array_builder_new());
    case GARROW_TYPE_INT16:
        return GARROW_ARRAY_BUILDER(garrow_int16_array_builder_new());
    case GARROW_TYPE_UINT16:
        return GARROW_ARRAY_BUILDER(garrow_uint16_array_builder_new());
    case GARROW_TYPE_INT32:
        return GARROW_ARRAY_BUILDER(garrow_int32_array_builder_new());
    case GARROW_TYPE_UINT32:
        return GARROW_ARRAY_BUILDER(garrow_uint32_array_builder_new());
    case GARROW_TYPE_INT64:
        return GARROW_ARRAY_BUILDER(garrow_int64_array_builder_new());
    case GARROW_TYPE_UINT64:
        return GARROW_ARRAY_BUILDER(garrow_uint64_array_builder_new());
    case GARROW_TYPE_FLOAT:
        return GARROW_ARRAY_BUILDER(garrow_float_array_builder_new());
    case GARROW_TYPE_DOUBLE:
        return GARROW_ARRAY_BUILDER(garrow_double_array_builder_new());
    default:
        return NULL;
    }
}

/* Arrow strings may contain embedded NUL bytes; GLib validates one segment at a time. */
static gboolean valid_utf8(const char *text, size_t length)
{
    const char *end;
    size_t segment;

    while (length > 0) {
        end = memchr(text, '\0', length);
        segment = end == NULL ? length : (size_t) (end - text);
        if (!g_utf8_validate(text, segment, NULL)) {
            return FALSE;
        }
        if (end == NULL) {
            break;
        }
        text += segment + 1;
        length -= segment + 1;
    }
    return TRUE;
}

static gboolean append_value(GArrowArrayBuilder *builder, const msgpack_object *value,
                             gboolean nullable, GError **error)
{
    GArrowType type;
    int64_t signed_value;
    uint64_t unsigned_value;
    double number;
    char *json;
    const char *text;
    size_t length;
    gboolean result;

    if (value == NULL || value->type == MSGPACK_OBJECT_NIL) {
        return nullable && garrow_array_builder_append_null(builder, error);
    }
    type = garrow_array_builder_get_value_type(builder);
    switch (type) {
    case GARROW_TYPE_BOOLEAN:
        return value->type == MSGPACK_OBJECT_BOOLEAN &&
               garrow_boolean_array_builder_append_value(GARROW_BOOLEAN_ARRAY_BUILDER(builder),
                                                         value->via.boolean, error);
    case GARROW_TYPE_STRING:
        json = NULL;
        if (value->type == MSGPACK_OBJECT_STR) {
            text = value->via.str.ptr;
            length = value->via.str.size;
        }
        else if (value->type == MSGPACK_OBJECT_MAP || value->type == MSGPACK_OBJECT_ARRAY) {
            json = flb_msgpack_to_json_str(256, value, FLB_FALSE);
            if (json == NULL) {
                return FALSE;
            }
            text = json;
            length = strlen(json);
        }
        else {
            return FALSE;
        }
        result = length <= INT32_MAX && valid_utf8(text, length) &&
                 garrow_binary_array_builder_append_value(GARROW_BINARY_ARRAY_BUILDER(builder),
                                                          (const guint8 *) text, length, error);
        flb_free(json);
        return result;
    case GARROW_TYPE_FLOAT:
    case GARROW_TYPE_DOUBLE:
        if (value->type == MSGPACK_OBJECT_FLOAT32 || value->type == MSGPACK_OBJECT_FLOAT64) {
            number = value->via.f64;
        }
        else if (value->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
            number = (double) value->via.u64;
        }
        else if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
            number = (double) value->via.i64;
        }
        else {
            return FALSE;
        }
        if (!isfinite(number)) {
            return FALSE;
        }
        if (type == GARROW_TYPE_FLOAT) {
            return fabs(number) <= FLT_MAX &&
                   garrow_float_array_builder_append_value(GARROW_FLOAT_ARRAY_BUILDER(builder),
                                                           (float) number, error);
        }
        return garrow_double_array_builder_append_value(GARROW_DOUBLE_ARRAY_BUILDER(builder),
                                                        number, error);
    default:
        break;
    }

    if (value->type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
        value->type != MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        return FALSE;
    }
    unsigned_value = value->via.u64;
    signed_value = value->via.i64;
    switch (type) {
    case GARROW_TYPE_INT8:
        if ((value->type == MSGPACK_OBJECT_POSITIVE_INTEGER && unsigned_value > INT8_MAX) ||
            (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER && signed_value < INT8_MIN)) {
            return FALSE;
        }
        return garrow_int8_array_builder_append_value(GARROW_INT8_ARRAY_BUILDER(builder),
                                                      (gint8) signed_value, error);
    case GARROW_TYPE_UINT8:
        if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER || unsigned_value > UINT8_MAX) {
            return FALSE;
        }
        return garrow_uint8_array_builder_append_value(GARROW_UINT8_ARRAY_BUILDER(builder),
                                                       (guint8) unsigned_value, error);
    case GARROW_TYPE_INT16:
        if ((value->type == MSGPACK_OBJECT_POSITIVE_INTEGER && unsigned_value > INT16_MAX) ||
            (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER && signed_value < INT16_MIN)) {
            return FALSE;
        }
        return garrow_int16_array_builder_append_value(GARROW_INT16_ARRAY_BUILDER(builder),
                                                      (gint16) signed_value, error);
    case GARROW_TYPE_UINT16:
        if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER || unsigned_value > UINT16_MAX) {
            return FALSE;
        }
        return garrow_uint16_array_builder_append_value(GARROW_UINT16_ARRAY_BUILDER(builder),
                                                       (guint16) unsigned_value, error);
    case GARROW_TYPE_INT32:
        if ((value->type == MSGPACK_OBJECT_POSITIVE_INTEGER && unsigned_value > INT32_MAX) ||
            (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER && signed_value < INT32_MIN)) {
            return FALSE;
        }
        return garrow_int32_array_builder_append_value(GARROW_INT32_ARRAY_BUILDER(builder),
                                                      (gint32) signed_value, error);
    case GARROW_TYPE_UINT32:
        if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER || unsigned_value > UINT32_MAX) {
            return FALSE;
        }
        return garrow_uint32_array_builder_append_value(GARROW_UINT32_ARRAY_BUILDER(builder),
                                                       (guint32) unsigned_value, error);
    case GARROW_TYPE_INT64:
        if ((value->type == MSGPACK_OBJECT_POSITIVE_INTEGER && unsigned_value > INT64_MAX) ||
            (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER && signed_value < INT64_MIN)) {
            return FALSE;
        }
        return garrow_int64_array_builder_append_value(GARROW_INT64_ARRAY_BUILDER(builder),
                                                      (gint64) signed_value, error);
    case GARROW_TYPE_UINT64:
        if (value->type == MSGPACK_OBJECT_NEGATIVE_INTEGER || unsigned_value > UINT64_MAX) {
            return FALSE;
        }
        return garrow_uint64_array_builder_append_value(GARROW_UINT64_ARRAY_BUILDER(builder),
                                                       (guint64) unsigned_value, error);
    default:
        return FALSE;
    }
}

GArrowTable *flb_arrow_schema_table(struct flb_arrow_schema *schema,
                                  const void *data, size_t size)
{
    struct flb_log_event_decoder decoder;
    struct flb_log_event event;
    GPtrArray *builders;
    GPtrArray *arrays;
    GList *fields;
    GList *entry;
    GArrowDataType *type;
    GArrowArray *array;
    GArrowTable *table = NULL;
    GError *error = NULL;
    const msgpack_object *value;
    guint i;
    int ret;
    int32_t record_type;

    if (schema == NULL ||
        flb_log_event_decoder_init(&decoder, (char *) data, size) != FLB_EVENT_DECODER_SUCCESS) {
        return NULL;
    }
    fields = garrow_schema_get_fields(schema->schema);
    builders = g_ptr_array_new_with_free_func(g_object_unref);
    arrays = g_ptr_array_new_with_free_func(g_object_unref);
    for (entry = fields; entry != NULL; entry = entry->next) {
        type = garrow_field_get_data_type(entry->data);
        g_ptr_array_add(builders, new_builder(garrow_data_type_get_id(type)));
    }
    flb_log_event_decoder_read_groups(&decoder, FLB_TRUE);
    while (decoder.offset < size) {
        ret = flb_log_event_decoder_next(&decoder, &event);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            goto done;
        }
        ret = flb_log_event_decoder_get_record_type(&event, &record_type);
        if (ret != 0) {
            goto done;
        }
        if (record_type != FLB_LOG_EVENT_NORMAL) {
            continue;
        }
        i = 0;
        for (entry = fields; entry != NULL; entry = entry->next, i++) {
            value = member(event.body, garrow_field_get_name(entry->data));
            if (!append_value(g_ptr_array_index(builders, i), value,
                              garrow_field_is_nullable(entry->data), &error)) {
                flb_error("[aws][arrow] value does not match column '%s'",
                          garrow_field_get_name(entry->data));
                goto done;
            }
        }
    }
    for (i = 0; i < builders->len; i++) {
        array = garrow_array_builder_finish(g_ptr_array_index(builders, i), &error);
        if (array == NULL) {
            goto done;
        }
        g_ptr_array_add(arrays, array);
    }
    table = garrow_table_new_arrays(schema->schema, (GArrowArray **) arrays->pdata,
                                    arrays->len, &error);
done:
    if (error != NULL) {
        flb_error("[aws][arrow] %s", error->message);
        g_error_free(error);
    }
    g_ptr_array_unref(arrays);
    g_ptr_array_unref(builders);
    g_list_free_full(fields, g_object_unref);
    flb_log_event_decoder_destroy(&decoder);
    return table;
}
