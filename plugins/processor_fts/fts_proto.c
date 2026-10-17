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

#include <fluent-bit/flb_mem.h>
#include <opentelemetry/proto/common/v1/common.pb-c.h>
#include "fts_proto.h"

/* Reflection is confined to the OTLP schema; policies see typed telemetry values. */
static int reserve(struct fts_proto_budget *budget, size_t size)
{
    if (size > budget->limit || budget->used > budget->limit - size) {
        return -1;
    }

    budget->used += size;
    return 0;
}

void *fts_proto_alloc(void *data, size_t size)
{
    void *ptr;

    if (reserve(data, size) != 0) {
        return NULL;
    }

    ptr = calloc(1, size ? size : 1);
    if (!ptr) {
        flb_errno();
    }

    return ptr;
}

void fts_proto_free(void *data, void *ptr)
{
    free(ptr);
}

static size_t scalar_size(ProtobufCType type)
{
    switch (type) {
    case PROTOBUF_C_TYPE_MESSAGE:
    case PROTOBUF_C_TYPE_STRING:
        return sizeof(void *);
    case PROTOBUF_C_TYPE_BYTES:
        return sizeof(ProtobufCBinaryData);
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
    case PROTOBUF_C_TYPE_SFIXED64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_DOUBLE:
        return 8;
    default:
        return 4;
    }
}

static int is_key_value(const ProtobufCFieldDescriptor *field)
{
    const ProtobufCMessageDescriptor *descriptor;

    if (field->type != PROTOBUF_C_TYPE_MESSAGE) {
        return FLB_FALSE;
    }

    descriptor = field->descriptor;
    return strcmp(descriptor->short_name, "KeyValue") == 0;
}

static struct cfl_variant *read_scalar(const ProtobufCFieldDescriptor *field, const void *ptr,
                                       struct fts_proto_budget *budget, int depth)
{
    const ProtobufCBinaryData *bytes;
    const char *string;

    if (reserve(budget, 256) != 0) {
        return NULL;
    }

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        return fts_proto_read(*(ProtobufCMessage *const *) ptr, budget, depth + 1);
    case PROTOBUF_C_TYPE_STRING:
        string = *(const char *const *) ptr;
        string = string ? string : "";
        if (reserve(budget, strlen(string) + 1) != 0) {
            return NULL;
        }
        return cfl_variant_create_from_string((char *) string);
    case PROTOBUF_C_TYPE_BYTES:
        bytes = ptr;
        if (reserve(budget, bytes->len) != 0) {
            return NULL;
        }
        return cfl_variant_create_from_bytes((char *) bytes->data, bytes->len, CFL_FALSE);
    case PROTOBUF_C_TYPE_BOOL:
        return cfl_variant_create_from_bool(*(const protobuf_c_boolean *) ptr);
    case PROTOBUF_C_TYPE_ENUM:
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
        return cfl_variant_create_from_int64(*(const int32_t *) ptr);
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        return cfl_variant_create_from_uint64(*(const uint32_t *) ptr);
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
        return cfl_variant_create_from_int64(*(const int64_t *) ptr);
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        return cfl_variant_create_from_uint64(*(const uint64_t *) ptr);
    case PROTOBUF_C_TYPE_DOUBLE:
        return cfl_variant_create_from_double(*(const double *) ptr);
    default:
        return NULL;
    }
}

static struct cfl_variant *read_repeated(const ProtobufCFieldDescriptor *field,
                                         const ProtobufCMessage *message,
                                         struct fts_proto_budget *budget, int depth)
{
    size_t count;
    size_t i;
    const char *items;
    struct cfl_variant *result;
    struct cfl_variant *child;
    struct cfl_kvlist *map;
    struct cfl_array *array;
    Opentelemetry__Proto__Common__V1__KeyValue *pair;

    count = *(const size_t *) ((const char *) message + field->quantifier_offset);
    items = *(const char *const *) ((const char *) message + field->offset);

    if (count > (SIZE_MAX - 256) / 256 || reserve(budget, count * 256 + 256) != 0) {
        return NULL;
    }

    if (is_key_value(field)) {
        map = cfl_kvlist_create();
        if (!map) {
            return NULL;
        }
        result = cfl_variant_create_from_kvlist(map);
        if (!result) {
            cfl_kvlist_destroy(map);
            return NULL;
        }
    }
    else {
        array = cfl_array_create(count);
        if (!array) {
            return NULL;
        }
        result = cfl_variant_create_from_array(array);
        if (!result) {
            cfl_array_destroy(array);
            return NULL;
        }
    }

    for (i = 0; i < count; i++) {
        if (is_key_value(field)) {
            pair = ((Opentelemetry__Proto__Common__V1__KeyValue *const *) items)[i];
            if (!pair || !pair->key) {
                goto failure;
            }
            child = fts_proto_read((ProtobufCMessage *) pair->value, budget, depth + 1);
            if (!child || cfl_kvlist_insert(result->data.as_kvlist, pair->key, child) != 0) {
                cfl_variant_destroy(child);
                goto failure;
            }
        }
        else {
            child = read_scalar(field, items + i * scalar_size(field->type), budget, depth);
            if (!child || cfl_array_append(result->data.as_array, child) != 0) {
                cfl_variant_destroy(child);
                goto failure;
            }
        }
    }

    return result;

failure:
    cfl_variant_destroy(result);
    return NULL;
}

struct cfl_variant *fts_proto_read(const ProtobufCMessage *message,
                                  struct fts_proto_budget *budget, int depth)
{
    const ProtobufCMessageDescriptor *descriptor;
    const ProtobufCFieldDescriptor *field;
    struct cfl_variant *result;
    struct cfl_variant *child;
    const char *ptr;
    size_t i;
    int any;
    int wrapper;

    if (depth > FTS_MAX_DEPTH || reserve(budget, 256) != 0) {
        return NULL;
    }

    if (!message) {
        return cfl_variant_create_from_null();
    }

    descriptor = message->descriptor;
    any = strcmp(descriptor->short_name, "AnyValue") == 0;
    wrapper = strcmp(descriptor->short_name, "ArrayValue") == 0 ||
              strcmp(descriptor->short_name, "KeyValueList") == 0;

    result = cfl_variant_create_from_kvlist(cfl_kvlist_create());
    if (!result) {
        return NULL;
    }

    for (i = 0; i < descriptor->n_fields; i++) {
        field = &descriptor->fields[i];
        ptr = (const char *) message;

        if ((field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) &&
            *(const uint32_t *) (ptr + field->quantifier_offset) != field->id) {
            continue;
        }

        if (field->label == PROTOBUF_C_LABEL_OPTIONAL && field->quantifier_offset &&
            !(field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) &&
            !*(const protobuf_c_boolean *) (ptr + field->quantifier_offset)) {
            continue;
        }

        if (field->label != PROTOBUF_C_LABEL_REPEATED && field->type == PROTOBUF_C_TYPE_MESSAGE &&
            !*(const ProtobufCMessage *const *) (ptr + field->offset)) {
            continue;
        }

        if (field->label == PROTOBUF_C_LABEL_REPEATED) {
            child = read_repeated(field, message, budget, depth);
        }
        else {
            child = read_scalar(field, ptr + field->offset, budget, depth);
        }

        if (!child) {
            cfl_variant_destroy(result);
            return NULL;
        }

        if (any || wrapper) {
            cfl_variant_destroy(result);
            return child;
        }

        if (reserve(budget, strlen(field->name) + 128) != 0 ||
            cfl_kvlist_insert(result->data.as_kvlist, (char *) field->name, child) != 0) {
            cfl_variant_destroy(child);
            cfl_variant_destroy(result);
            return NULL;
        }
    }

    if (any) {
        cfl_variant_destroy(result);
        return cfl_variant_create_from_null();
    }

    return result;
}

static int signed_integer(struct cfl_variant *value, int64_t *result)
{
    if (value->type == CFL_VARIANT_INT) {
        *result = value->data.as_int64;
        return 0;
    }

    if (value->type == CFL_VARIANT_UINT && value->data.as_uint64 <= INT64_MAX) {
        *result = (int64_t) value->data.as_uint64;
        return 0;
    }

    return -1;
}

static int unsigned_integer(struct cfl_variant *value, uint64_t *result)
{
    if (value->type == CFL_VARIANT_UINT) {
        *result = value->data.as_uint64;
        return 0;
    }

    if (value->type == CFL_VARIANT_INT && value->data.as_int64 >= 0) {
        *result = (uint64_t) value->data.as_int64;
        return 0;
    }

    return -1;
}

static int write_scalar(const ProtobufCFieldDescriptor *field, struct cfl_variant *value,
                         void *ptr, struct fts_proto_budget *budget, int depth)
{
    int64_t signed_value;
    uint64_t unsigned_value;
    size_t size;
    char *string;
    ProtobufCBinaryData *bytes;

    switch (field->type) {
    case PROTOBUF_C_TYPE_MESSAGE:
        *(ProtobufCMessage **) ptr = fts_proto_build(field->descriptor, value, budget, depth + 1);
        return *(ProtobufCMessage **) ptr ? 0 : -1;
    case PROTOBUF_C_TYPE_STRING:
        if (value->type != CFL_VARIANT_STRING) {
            return -1;
        }
        size = cfl_variant_size_get(value);
        if (memchr(value->data.as_string, 0, size) ||
            !fts_valid_utf8(value->data.as_string, size) || reserve(budget, size + 1) != 0) {
            return -1;
        }

        string = malloc(size + 1);
        if (!string) {
            flb_errno();
            return -1;
        }

        memcpy(string, value->data.as_string, size);
        string[size] = 0;
        *(char **) ptr = string;
        return 0;
    case PROTOBUF_C_TYPE_BYTES:
        if (value->type != CFL_VARIANT_BYTES) {
            return -1;
        }
        size = cfl_variant_size_get(value);
        bytes = ptr;
        bytes->data = fts_proto_alloc(budget, size);
        if (!bytes->data) {
            return -1;
        }

        bytes->len = size;
        memcpy(bytes->data, value->data.as_bytes, size);
        return 0;
    case PROTOBUF_C_TYPE_BOOL:
        if (value->type != CFL_VARIANT_BOOL) {
            return -1;
        }
        *(protobuf_c_boolean *) ptr = value->data.as_bool;
        return 0;
    case PROTOBUF_C_TYPE_ENUM:
    case PROTOBUF_C_TYPE_INT32:
    case PROTOBUF_C_TYPE_SINT32:
    case PROTOBUF_C_TYPE_SFIXED32:
        if (signed_integer(value, &signed_value) != 0 ||
            signed_value < INT32_MIN || signed_value > INT32_MAX) {
            return -1;
        }
        *(int32_t *) ptr = (int32_t) signed_value;
        return 0;
    case PROTOBUF_C_TYPE_UINT32:
    case PROTOBUF_C_TYPE_FIXED32:
        if (unsigned_integer(value, &unsigned_value) != 0 || unsigned_value > UINT32_MAX) {
            return -1;
        }
        *(uint32_t *) ptr = (uint32_t) unsigned_value;
        return 0;
    case PROTOBUF_C_TYPE_INT64:
    case PROTOBUF_C_TYPE_SINT64:
    case PROTOBUF_C_TYPE_SFIXED64:
        return signed_integer(value, ptr);
    case PROTOBUF_C_TYPE_UINT64:
    case PROTOBUF_C_TYPE_FIXED64:
        return unsigned_integer(value, ptr);
    case PROTOBUF_C_TYPE_DOUBLE:
        if (value->type == CFL_VARIANT_DOUBLE) {
            *(double *) ptr = value->data.as_double;
        }
        else {
            return -1;
        }
        return 0;
    default:
        return -1;
    }
}

static int write_repeated(const ProtobufCFieldDescriptor *field, struct cfl_variant *value,
                           ProtobufCMessage *message, struct fts_proto_budget *budget, int depth)
{
    size_t count;
    size_t i;
    size_t stride;
    char *items;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    Opentelemetry__Proto__Common__V1__KeyValue *entry;
    ProtobufCMessage **messages;

    if (is_key_value(field)) {
        if (value->type != CFL_VARIANT_KVLIST) {
            return -1;
        }
        count = cfl_list_size(&value->data.as_kvlist->list);
    }
    else {
        if (value->type != CFL_VARIANT_ARRAY) {
            return -1;
        }
        count = value->data.as_array->entry_count;
    }

    stride = scalar_size(field->type);
    if (count > SIZE_MAX / stride) {
        return -1;
    }

    items = fts_proto_alloc(budget, count * stride);
    if (!items) {
        return -1;
    }

    *(void **) ((char *) message + field->offset) = items;
    *(size_t *) ((char *) message + field->quantifier_offset) = count;

    if (is_key_value(field)) {
        i = 0;
        messages = (ProtobufCMessage **) items;
        cfl_list_foreach(head, &value->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            entry = fts_proto_alloc(budget, sizeof(*entry));
            if (!entry) {
                return -1;
            }

            opentelemetry__proto__common__v1__key_value__init(entry);
            messages[i++] = &entry->base;

            if (memchr(pair->key, 0, cfl_sds_len(pair->key)) ||
                !fts_valid_utf8(pair->key, cfl_sds_len(pair->key)) ||
                reserve(budget, cfl_sds_len(pair->key) + 1) != 0) {
                return -1;
            }

            /*
             * protobuf-c releases the message with the system allocator, so
             * the key is copied with malloc() like every other string.
             */
            entry->key = malloc(cfl_sds_len(pair->key) + 1);
            if (!entry->key) {
                flb_errno();
                return -1;
            }
            memcpy(entry->key, pair->key, cfl_sds_len(pair->key) + 1);

            entry->value = (void *) fts_proto_build(
                                &opentelemetry__proto__common__v1__any_value__descriptor,
                                pair->val, budget, depth + 1);

            if (!entry->value) {
                return -1;
            }
        }
    }
    else {
        for (i = 0; i < count; i++) {
            if (write_scalar(field, value->data.as_array->entries[i], items + i * stride,
                             budget, depth) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

ProtobufCMessage *fts_proto_build(const ProtobufCMessageDescriptor *descriptor,
                                  struct cfl_variant *value,
                                  struct fts_proto_budget *budget, int depth)
{
    ProtobufCMessage *message;
    const ProtobufCFieldDescriptor *field;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    int any;
    int wrapper;
    const char *name;
    uint32_t *oneof;

    if (depth > FTS_MAX_DEPTH) {
        return NULL;
    }

    /* An adapter may retain a failed original item as opaque transport data.
     * This path is private staging; policies never receive opaque messages. */
    if (value->type == CFL_VARIANT_BYTES &&
        (strcmp(descriptor->short_name, "ResourceMetrics") == 0 ||
         strcmp(descriptor->short_name, "ResourceSpans") == 0)) {
        return protobuf_c_message_unpack(descriptor, NULL, cfl_variant_size_get(value),
                                          (uint8_t *) value->data.as_bytes);
    }

    message = fts_proto_alloc(budget, descriptor->sizeof_message);
    if (!message) {
        return NULL;
    }

    descriptor->message_init(message);
    any = strcmp(descriptor->short_name, "AnyValue") == 0;
    wrapper = strcmp(descriptor->short_name, "ArrayValue") == 0 ||
              strcmp(descriptor->short_name, "KeyValueList") == 0;

    if (any) {
        switch (value->type) {
        case CFL_VARIANT_NULL:
            return message;
        case CFL_VARIANT_STRING:
            name = "string_value";
            break;
        case CFL_VARIANT_BYTES:
            name = "bytes_value";
            break;
        case CFL_VARIANT_BOOL:
            name = "bool_value";
            break;
        case CFL_VARIANT_INT:
        case CFL_VARIANT_UINT:
            name = "int_value";
            break;
        case CFL_VARIANT_DOUBLE:
            name = "double_value";
            break;
        case CFL_VARIANT_ARRAY:
            name = "array_value";
            break;
        case CFL_VARIANT_KVLIST:
            name = "kvlist_value";
            break;
        default:
            goto failure;
        }

        field = protobuf_c_message_descriptor_get_field_by_name(descriptor, name);
        *(uint32_t *) ((char *) message + field->quantifier_offset) = field->id;

        if (write_scalar(field, value, (char *) message + field->offset, budget, depth) != 0) {
            goto failure;
        }
        return message;
    }

    if (wrapper) {
        if (write_repeated(&descriptor->fields[0], value, message, budget, depth) != 0) {
            goto failure;
        }
        return message;
    }

    if (value->type != CFL_VARIANT_KVLIST) {
        goto failure;
    }

    cfl_list_foreach(head, &value->data.as_kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        field = protobuf_c_message_descriptor_get_field_by_name(descriptor, pair->key);
        if (!field || memchr(pair->key, 0, cfl_sds_len(pair->key)) ||
            fts_find_pair(value, pair->key, cfl_sds_len(pair->key)) != pair) {
            goto failure;
        }

        if (field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF) {
            oneof = (uint32_t *) ((char *) message + field->quantifier_offset);
            if (*oneof != 0) {
                goto failure;
            }
            *oneof = field->id;
        }
        else if (field->label == PROTOBUF_C_LABEL_OPTIONAL && field->quantifier_offset) {
            *(protobuf_c_boolean *) ((char *) message + field->quantifier_offset) = 1;
        }

        if (field->label == PROTOBUF_C_LABEL_REPEATED) {
            if (write_repeated(field, pair->val, message, budget, depth) != 0) {
                goto failure;
            }
        }
        else if (write_scalar(field, pair->val, (char *) message + field->offset,
                              budget, depth) != 0) {
            goto failure;
        }
    }

    return message;

failure:
    protobuf_c_message_free_unpacked(message, NULL);
    return NULL;
}
