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

/*
 * EXPERIMENTAL: CFL map views over OTLP protobuf log records.
 *
 * An encoded ExportLogsServiceRequest is walked on the wire format. The
 * attributes of each LogRecord are exposed as a view whose entries borrow
 * the key bytes and point at the encoded KeyValue. Nothing is decoded into
 * objects. Records that the editor leaves alone are copied as raw spans;
 * edited records are rebuilt from raw spans plus the encoded edits, and only
 * the length prefixes of their parents are rewritten. Unknown fields are
 * preserved at every level.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_log_view.h>
#include <fluent-bit/flb_opentelemetry_view.h>
#include <fluent-bit/flb_log_event.h>
#include <fluent-bit/flb_time.h>
#include <fluent-otel-proto/fluent-otel.h>

#include <errno.h>
#include <string.h>

#define WIRE_VARINT   0
#define WIRE_FIXED64  1
#define WIRE_LEN      2
#define WIRE_FIXED32  5

/*
 * Nesting of an AnyValue. The value of a record, body or attribute, is at
 * depth 1, which keeps the reader within what the request validation allows:
 * nothing it rejects for its nesting is accepted here.
 */
#define ANY_VALUE_DEPTH 32

struct wire_field {
    uint32_t number;
    int type;
    const uint8_t *start;                  /* first byte of the tag */
    const uint8_t *end;                    /* one past the field */
    const uint8_t *data;                   /* payload of a LEN field */
    size_t size;
    uint64_t value;                        /* varint and fixed values */
};

static int wire_varint_long(const uint8_t **cursor, const uint8_t *end, uint64_t *value)
{
    const uint8_t *p = *cursor;
    uint64_t result = 0;
    int shift;

    for (shift = 0; shift < 64 && p < end; shift += 7) {
        if (shift == 63 && *p > 1) {
            /* more than 64 bits: flb_opentelemetry_protobuf_validate() rejects it too */
            return -1;
        }
        result |= (uint64_t) (*p & 0x7f) << shift;
        if ((*p++ & 0x80) == 0) {
            *cursor = p;
            *value = result;
            return 0;
        }
    }

    return -1;
}

/* Tags, lengths and most values of a log request fit in one byte. */
static FLB_INLINE int wire_varint(const uint8_t **cursor, const uint8_t *end, uint64_t *value)
{
    const uint8_t *p = *cursor;

    if (p < end && *p < 0x80) {
        *value = *p;
        *cursor = p + 1;
        return 0;
    }

    return wire_varint_long(cursor, end, value);
}

/* Fixed-width values are little endian on the wire, whatever the host is. */
static FLB_INLINE uint32_t wire_fixed32(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) |
           ((uint32_t) p[3] << 24);
}

static FLB_INLINE uint64_t wire_fixed64(const uint8_t *p)
{
    return (uint64_t) wire_fixed32(p) | ((uint64_t) wire_fixed32(p + 4) << 32);
}

/* Returns 1 with a field, 0 at the end of the message and -1 when malformed. */
static FLB_INLINE int wire_next(const uint8_t **cursor, const uint8_t *end,
                                struct wire_field *field)
{
    const uint8_t *p = *cursor;
    uint64_t key;
    uint64_t size;

    if (p >= end) {
        return 0;
    }

    field->start = p;
    if (wire_varint(&p, end, &key) != 0 || (key >> 3) == 0 || (key >> 3) > 0x1fffffff) {
        return -1;
    }
    field->number = (uint32_t) (key >> 3);
    field->type = (int) (key & 7);
    field->data = NULL;
    field->size = 0;
    field->value = 0;

    switch (field->type) {
    case WIRE_VARINT:
        if (wire_varint(&p, end, &field->value) != 0) {
            return -1;
        }
        break;
    case WIRE_FIXED64:
        if ((size_t) (end - p) < 8) {
            return -1;
        }
        field->value = wire_fixed64(p);
        p += 8;
        break;
    case WIRE_FIXED32:
        if ((size_t) (end - p) < 4) {
            return -1;
        }
        field->value = wire_fixed32(p);
        p += 4;
        break;
    case WIRE_LEN:
        if (wire_varint(&p, end, &size) != 0 || size > (size_t) (end - p)) {
            return -1;
        }
        field->data = p;
        field->size = (size_t) size;
        p += size;
        break;
    default:
        /* groups are not part of OTLP */
        return -1;
    }

    field->end = p;
    *cursor = p;

    return 1;
}

/* Output buffer with canonical length prefixes written after the content. */
struct wire_out {
    uint8_t *data;
    size_t size;
    size_t capacity;
    int error;
};

static int out_reserve(struct wire_out *out, size_t extra)
{
    uint8_t *data;
    size_t capacity;

    if (out->error != 0) {
        return -1;
    }
    if (extra <= out->capacity - out->size) {
        return 0;
    }

    capacity = out->capacity ? out->capacity : 4096;
    while (capacity - out->size < extra) {
        if (capacity > SIZE_MAX / 2) {
            out->error = ENOMEM;
            return -1;
        }
        capacity *= 2;
    }
    data = flb_realloc(out->data, capacity);
    if (data == NULL) {
        flb_errno();
        out->error = ENOMEM;
        return -1;
    }
    out->data = data;
    out->capacity = capacity;

    return 0;
}

static void out_bytes(struct wire_out *out, const void *data, size_t size)
{
    if (size > 0 && out_reserve(out, size) == 0) {
        memcpy(out->data + out->size, data, size);
        out->size += size;
    }
}

static size_t varint_size(uint64_t value)
{
    size_t size = 1;

    while (value >= 0x80) {
        value >>= 7;
        size++;
    }

    return size;
}

static size_t varint_write(uint8_t *target, uint64_t value)
{
    size_t size = 0;

    while (value >= 0x80) {
        target[size++] = (uint8_t) (value | 0x80);
        value >>= 7;
    }
    target[size++] = (uint8_t) value;

    return size;
}

static void out_varint(struct wire_out *out, uint64_t value)
{
    if (out_reserve(out, 10) == 0) {
        out->size += varint_write(out->data + out->size, value);
    }
}

static void out_tag(struct wire_out *out, uint32_t number, int type)
{
    out_varint(out, ((uint64_t) number << 3) | (uint64_t) type);
}

static void out_fixed64(struct wire_out *out, uint64_t value)
{
    uint8_t bytes[8];
    int index;

    for (index = 0; index < 8; index++) {
        bytes[index] = (uint8_t) (value >> (8 * index));
    }
    out_bytes(out, bytes, sizeof(bytes));
}

/*
 * Open a nested message whose size is not known yet. The prefix is reserved
 * with the width of the original size, which is right unless an edit moves
 * the size across a varint boundary.
 */
static size_t out_open(struct wire_out *out, size_t expected, size_t *reserved)
{
    size_t mark = out->size;

    *reserved = varint_size(expected);
    if (out_reserve(out, *reserved) == 0) {
        out->size += *reserved;
    }

    return mark;
}

static void out_close(struct wire_out *out, size_t mark, size_t reserved)
{
    size_t content;
    size_t needed;

    if (out->error != 0) {
        return;
    }

    content = out->size - mark - reserved;
    needed = varint_size(content);
    if (needed != reserved) {
        if (needed > reserved && out_reserve(out, needed - reserved) != 0) {
            return;
        }
        memmove(out->data + mark + needed, out->data + mark + reserved, content);
        out->size = mark + needed + content;
    }
    varint_write(out->data + mark, content);
}

/* AnyValue reading */

static int any_value_read(const uint8_t *data, size_t size, struct cfl_view_value *out)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    int result;

    /* an AnyValue without a set member is an empty value */
    out->type = CFL_VARIANT_NULL;
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        switch (field.number) {
        case 1:
            if (field.type != WIRE_LEN) {
                return -1;
            }
            out->type = CFL_VARIANT_STRING;
            out->data.as_bytes.data = (const char *) field.data;
            out->data.as_bytes.size = field.size;
            break;
        case 2:
            if (field.type != WIRE_VARINT) {
                return -1;
            }
            out->type = CFL_VARIANT_BOOL;
            out->data.as_bool = field.value != 0;
            break;
        case 3:
            if (field.type != WIRE_VARINT) {
                return -1;
            }
            out->type = CFL_VARIANT_INT;
            out->data.as_int64 = (int64_t) field.value;
            break;
        case 4:
            if (field.type != WIRE_FIXED64) {
                return -1;
            }
            out->type = CFL_VARIANT_DOUBLE;
            memcpy(&out->data.as_double, &field.value, sizeof(double));
            break;
        case 5:
            if (field.type != WIRE_LEN) {
                return -1;
            }
            out->type = CFL_VARIANT_ARRAY;
            out->data.as_bytes.data = (const char *) field.data;
            out->data.as_bytes.size = field.size;
            break;
        case 6:
            if (field.type != WIRE_LEN) {
                return -1;
            }
            out->type = CFL_VARIANT_KVLIST;
            out->data.as_bytes.data = (const char *) field.data;
            out->data.as_bytes.size = field.size;
            break;
        case 7:
            if (field.type != WIRE_LEN) {
                return -1;
            }
            out->type = CFL_VARIANT_BYTES;
            out->data.as_bytes.data = (const char *) field.data;
            out->data.as_bytes.size = field.size;
            break;
        default:
            break;
        }
    }

    return result;
}

/* Key and AnyValue payload of an encoded KeyValue. The last occurrence wins. */
static int key_value_read(const uint8_t *data, size_t size,
                          struct cfl_view_ref *key, struct cfl_view_ref *value)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    int result;

    key->data = "";
    key->size = 0;
    value->data = NULL;
    value->size = 0;
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number == 1 && field.type == WIRE_LEN) {
            key->data = (const char *) field.data;
            key->size = field.size;
        }
        else if (field.number == 2 && field.type == WIRE_LEN) {
            value->data = (const char *) field.data;
            value->size = field.size;
        }
        else if (field.number == 1 || field.number == 2) {
            return -1;
        }
    }

    return result;
}

static struct cfl_variant *any_value_materialize(const uint8_t *data, size_t size, int depth);

static struct cfl_variant *kvlist_materialize(const uint8_t *data, size_t size, int depth)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct cfl_view_ref key;
    struct cfl_view_ref raw;
    struct wire_field field;
    struct cfl_kvlist *kvlist;
    struct cfl_variant *value;
    int result;

    kvlist = cfl_kvlist_create();
    if (kvlist == NULL) {
        return NULL;
    }

    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != 1 || field.type != WIRE_LEN) {
            continue;
        }
        if (key_value_read(field.data, field.size, &key, &raw) != 0) {
            result = -1;
            break;
        }
        value = any_value_materialize((const uint8_t *) raw.data, raw.size, depth + 1);
        if (value == NULL) {
            result = -1;
            break;
        }
        if (cfl_kvlist_insert_s(kvlist, (char *) key.data, key.size, value) != 0) {
            cfl_variant_destroy(value);
            result = -1;
            break;
        }
    }

    value = result == 0 ? cfl_variant_create_from_kvlist(kvlist) : NULL;
    if (value == NULL) {
        cfl_kvlist_destroy(kvlist);
    }

    return value;
}

static struct cfl_variant *array_materialize(const uint8_t *data, size_t size, int depth)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    struct cfl_array *array;
    struct cfl_variant *value;
    int result;

    array = cfl_array_create(8);
    if (array == NULL) {
        return NULL;
    }
    cfl_array_resizable(array, CFL_TRUE);

    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != 1 || field.type != WIRE_LEN) {
            continue;
        }
        value = any_value_materialize(field.data, field.size, depth + 1);
        if (value == NULL) {
            result = -1;
            break;
        }
        if (cfl_array_append(array, value) != 0) {
            cfl_variant_destroy(value);
            result = -1;
            break;
        }
    }

    value = result == 0 ? cfl_variant_create_from_array(array) : NULL;
    if (value == NULL) {
        cfl_array_destroy(array);
    }

    return value;
}

static struct cfl_variant *any_value_materialize(const uint8_t *data, size_t size, int depth)
{
    struct cfl_view_value value;
    const char *bytes;

    if (depth > ANY_VALUE_DEPTH || any_value_read(data, size, &value) != 0) {
        return NULL;
    }

    bytes = value.data.as_bytes.data;
    switch (value.type) {
    case CFL_VARIANT_STRING:
        return cfl_variant_create_from_string_s((char *) (value.data.as_bytes.size ? bytes : ""),
                                                value.data.as_bytes.size, CFL_FALSE);
    case CFL_VARIANT_BYTES:
        return cfl_variant_create_from_bytes((char *) (value.data.as_bytes.size ? bytes : ""),
                                             value.data.as_bytes.size, CFL_FALSE);
    case CFL_VARIANT_BOOL:
        return cfl_variant_create_from_bool(value.data.as_bool);
    case CFL_VARIANT_INT:
        return cfl_variant_create_from_int64(value.data.as_int64);
    case CFL_VARIANT_DOUBLE:
        return cfl_variant_create_from_double(value.data.as_double);
    case CFL_VARIANT_ARRAY:
        return array_materialize((const uint8_t *) bytes, value.data.as_bytes.size, depth);
    case CFL_VARIANT_KVLIST:
        return kvlist_materialize((const uint8_t *) bytes, value.data.as_bytes.size, depth);
    }

    return cfl_variant_create_from_null();
}

/*
 * View backend. The source handle of an entry is the first byte of its
 * encoded KeyValue field and the view context is the end of the record.
 */
static int attribute_field(struct cfl_view *view, const struct cfl_view_entry *entry,
                           struct wire_field *field)
{
    const uint8_t *cursor = entry->source.pointer;

    return wire_next(&cursor, view->context, field) == 1 ? 0 : -1;
}

static int attribute_value(struct cfl_view *view, const struct cfl_view_entry *entry,
                           struct cfl_view_value *out)
{
    struct cfl_view_ref key;
    struct cfl_view_ref raw;
    struct wire_field field;

    if (attribute_field(view, entry, &field) != 0 ||
        key_value_read(field.data, field.size, &key, &raw) != 0 ||
        any_value_read((const uint8_t *) raw.data, raw.size, out) != 0) {
        return -1;
    }
    if (out->type == CFL_VARIANT_ARRAY || out->type == CFL_VARIANT_KVLIST) {
        /* containers only report their type */
        out->data.as_bytes.data = NULL;
        out->data.as_bytes.size = 0;
    }

    return 0;
}

static struct cfl_variant *attribute_materialize(struct cfl_view *view,
                                                 const struct cfl_view_entry *entry)
{
    struct cfl_view_ref key;
    struct cfl_view_ref raw;
    struct wire_field field;

    if (attribute_field(view, entry, &field) != 0 ||
        key_value_read(field.data, field.size, &key, &raw) != 0) {
        return NULL;
    }

    return any_value_materialize((const uint8_t *) raw.data, raw.size, 0);
}

static const struct cfl_view_backend attribute_backend = {
    .name = "otlp_protobuf_attributes",
    .value = attribute_value,
    .materialize = attribute_materialize,
};

#define LOG_RECORD_ATTRIBUTES 6

int flb_opentelemetry_log_record_view_load(struct cfl_view *view,
                                           const void *record, size_t size)
{
    const uint8_t *cursor = record;
    const uint8_t *end = cursor + size;
    struct cfl_view_ref key;
    struct cfl_view_ref raw;
    struct wire_field field;
    int result;

    cfl_view_reset(view, &attribute_backend, (void *) end);
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != LOG_RECORD_ATTRIBUTES) {
            continue;
        }
        if (field.type != WIRE_LEN ||
            key_value_read(field.data, field.size, &key, &raw) != 0 ||
            cfl_view_load_pointer(view, key.data, key.size, (void *) field.start) != 0) {
            return -1;
        }
    }

    return result;
}

static void attribute_literal_write(struct wire_out *out, const struct cfl_view_entry *entry)
{
    const struct cfl_view_value *value = &entry->value;
    size_t record;
    size_t record_reserved;
    size_t any;
    size_t any_reserved;
    uint64_t bits;

    out_tag(out, LOG_RECORD_ATTRIBUTES, WIRE_LEN);
    record = out_open(out, entry->key.size + value->data.as_bytes.size + 6, &record_reserved);
    out_tag(out, 1, WIRE_LEN);
    out_varint(out, entry->key.size);
    out_bytes(out, entry->key.data, entry->key.size);
    out_tag(out, 2, WIRE_LEN);
    any = out_open(out, value->data.as_bytes.size + 2, &any_reserved);
    switch (value->type) {
    case CFL_VARIANT_STRING:
    case CFL_VARIANT_BYTES:
        out_tag(out, value->type == CFL_VARIANT_STRING ? 1 : 7, WIRE_LEN);
        out_varint(out, value->data.as_bytes.size);
        out_bytes(out, value->data.as_bytes.data, value->data.as_bytes.size);
        break;
    case CFL_VARIANT_BOOL:
        out_tag(out, 2, WIRE_VARINT);
        out_varint(out, value->data.as_bool ? 1 : 0);
        break;
    case CFL_VARIANT_INT:
        out_tag(out, 3, WIRE_VARINT);
        out_varint(out, (uint64_t) value->data.as_int64);
        break;
    case CFL_VARIANT_UINT:
        out_tag(out, 3, WIRE_VARINT);
        out_varint(out, value->data.as_uint64);
        break;
    case CFL_VARIANT_DOUBLE:
        memcpy(&bits, &value->data.as_double, sizeof(bits));
        out_tag(out, 4, WIRE_FIXED64);
        out_fixed64(out, bits);
        break;
    case CFL_VARIANT_NULL:
        break;
    default:
        out->error = EINVAL;
    }
    out_close(out, any, any_reserved);
    out_close(out, record, record_reserved);
}

/* The members of an AnyValue for a CFL object an editor placed in the view. */
static void any_variant_write(struct wire_out *out, struct cfl_variant *value, int depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_array *array;
    size_t list;
    size_t list_reserved;
    size_t item;
    size_t item_reserved;
    size_t any;
    size_t any_reserved;
    size_t index;
    uint64_t bits;

    if (value == NULL || depth > ANY_VALUE_DEPTH) {
        out->error = EINVAL;
        return;
    }

    switch (value->type) {
    case CFL_VARIANT_STRING:
    case CFL_VARIANT_BYTES:
        out_tag(out, value->type == CFL_VARIANT_STRING ? 1 : 7, WIRE_LEN);
        out_varint(out, cfl_variant_size_get(value));
        out_bytes(out, value->data.as_string, cfl_variant_size_get(value));
        break;
    case CFL_VARIANT_BOOL:
        out_tag(out, 2, WIRE_VARINT);
        out_varint(out, value->data.as_bool ? 1 : 0);
        break;
    case CFL_VARIANT_INT:
        out_tag(out, 3, WIRE_VARINT);
        out_varint(out, (uint64_t) value->data.as_int64);
        break;
    case CFL_VARIANT_UINT:
        out_tag(out, 3, WIRE_VARINT);
        out_varint(out, value->data.as_uint64);
        break;
    case CFL_VARIANT_DOUBLE:
        memcpy(&bits, &value->data.as_double, sizeof(bits));
        out_tag(out, 4, WIRE_FIXED64);
        out_fixed64(out, bits);
        break;
    case CFL_VARIANT_NULL:
        break;
    case CFL_VARIANT_ARRAY:
        array = value->data.as_array;
        out_tag(out, 5, WIRE_LEN);
        list = out_open(out, 0, &list_reserved);
        for (index = 0; array != NULL && index < array->entry_count; index++) {
            out_tag(out, 1, WIRE_LEN);
            item = out_open(out, 0, &item_reserved);
            any_variant_write(out, array->entries[index], depth + 1);
            out_close(out, item, item_reserved);
        }
        out_close(out, list, list_reserved);
        break;
    case CFL_VARIANT_KVLIST:
        out_tag(out, 6, WIRE_LEN);
        list = out_open(out, 0, &list_reserved);
        if (value->data.as_kvlist != NULL) {
            cfl_list_foreach(head, &value->data.as_kvlist->list) {
                pair = cfl_list_entry(head, struct cfl_kvpair, _head);
                out_tag(out, 1, WIRE_LEN);
                item = out_open(out, 0, &item_reserved);
                out_tag(out, 1, WIRE_LEN);
                out_varint(out, cfl_sds_len(pair->key));
                out_bytes(out, pair->key, cfl_sds_len(pair->key));
                out_tag(out, 2, WIRE_LEN);
                any = out_open(out, 0, &any_reserved);
                any_variant_write(out, pair->val, depth + 1);
                out_close(out, any, any_reserved);
                out_close(out, item, item_reserved);
            }
        }
        out_close(out, list, list_reserved);
        break;
    default:
        /* a reference has no OTLP form */
        out->error = EINVAL;
    }
}

static void attribute_variant_write(struct wire_out *out, const struct cfl_view_entry *entry)
{
    size_t record;
    size_t record_reserved;
    size_t any;
    size_t any_reserved;

    out_tag(out, LOG_RECORD_ATTRIBUTES, WIRE_LEN);
    record = out_open(out, entry->key.size + 6, &record_reserved);
    out_tag(out, 1, WIRE_LEN);
    out_varint(out, entry->key.size);
    out_bytes(out, entry->key.data, entry->key.size);
    out_tag(out, 2, WIRE_LEN);
    any = out_open(out, 0, &any_reserved);
    any_variant_write(out, entry->value.data.as_variant, 0);
    out_close(out, any, any_reserved);
    out_close(out, record, record_reserved);
}

/* A renamed pair: the new key, then every other field of the pair as it was. */
static void attribute_renamed_write(struct wire_out *out, struct cfl_view *view,
                                    const struct cfl_view_entry *entry)
{
    const uint8_t *cursor;
    const uint8_t *end;
    struct wire_field pair;
    struct wire_field field;
    size_t mark;
    size_t reserved;
    int result;

    if (attribute_field(view, entry, &pair) != 0) {
        out->error = EINVAL;
        return;
    }

    out_tag(out, LOG_RECORD_ATTRIBUTES, WIRE_LEN);
    mark = out_open(out, pair.size, &reserved);
    out_tag(out, 1, WIRE_LEN);
    out_varint(out, entry->key.size);
    out_bytes(out, entry->key.data, entry->key.size);
    cursor = pair.data;
    end = pair.data + pair.size;
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != 1) {
            out_bytes(out, field.start, (size_t) (field.end - field.start));
        }
    }
    if (result != 0) {
        out->error = EINVAL;
    }
    out_close(out, mark, reserved);
}

static void attributes_write(struct wire_out *out, struct cfl_view *view)
{
    const struct cfl_view_entry *entry;
    struct wire_field field;
    size_t index;

    for (index = 0; index < cfl_view_count(view) && out->error == 0; index++) {
        entry = cfl_view_entry_at(view, index);
        if (entry->origin == CFL_VIEW_ENTRY_LITERAL) {
            attribute_literal_write(out, entry);
        }
        else if (entry->origin == CFL_VIEW_ENTRY_VARIANT) {
            attribute_variant_write(out, entry);
        }
        else if (entry->origin != CFL_VIEW_ENTRY_SOURCE) {
            out->error = EINVAL;
        }
        else if (entry->key_changed) {
            attribute_renamed_write(out, view, entry);
        }
        else if (attribute_field(view, entry, &field) == 0) {
            out_bytes(out, field.start, (size_t) (field.end - field.start));
        }
        else {
            out->error = EINVAL;
        }
    }
}

struct transform {
    const struct flb_log_view_editor *editor;
    struct cfl_view view;
    struct wire_out *out;                  /* NULL for a read-only scan */
    size_t records;
    size_t modified;
};

static int transform_record(struct transform *state, const struct wire_field *record)
{
    const uint8_t *cursor;
    const uint8_t *end;
    struct flb_log_view log = {0};
    struct wire_field field;
    size_t mark;
    size_t reserved;
    int attributes_written;
    int result;

    if (flb_opentelemetry_log_record_view_load(&state->view, record->data, record->size) != 0) {
        return EINVAL;
    }
    log.otel_log_attributes = &state->view;
    if (state->editor->cb_record(state->editor->data, &log) != 0) {
        return ECANCELED;
    }
    state->records++;
    if (state->out == NULL) {
        return 0;
    }
    if (!state->view.modified) {
        /* untouched record: one raw span, length prefix included */
        out_bytes(state->out, record->start, (size_t) (record->end - record->start));
        return state->out->error;
    }

    state->modified++;
    out_tag(state->out, record->number, WIRE_LEN);
    mark = out_open(state->out, record->size, &reserved);
    attributes_written = FLB_FALSE;
    cursor = record->data;
    end = record->data + record->size;
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != LOG_RECORD_ATTRIBUTES) {
            out_bytes(state->out, field.start, (size_t) (field.end - field.start));
        }
        else if (!attributes_written) {
            /* keep the attributes where the record had them */
            attributes_write(state->out, &state->view);
            attributes_written = FLB_TRUE;
        }
    }
    if (!attributes_written) {
        attributes_write(state->out, &state->view);
    }
    out_close(state->out, mark, reserved);

    return result != 0 ? EINVAL : state->out->error;
}

/*
 * ExportLogsServiceRequest.resource_logs (1) > ResourceLogs.scope_logs (2) >
 * ScopeLogs.log_records (2). Every other field is copied as it is.
 */
static int transform_message(struct transform *state, const uint8_t *data, size_t size,
                             int level)
{
    static const uint32_t nested[] = {1, 2, 2};
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    size_t mark;
    size_t reserved;
    int result;
    int status;

    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != nested[level] || field.type != WIRE_LEN) {
            if (state->out != NULL) {
                out_bytes(state->out, field.start, (size_t) (field.end - field.start));
            }
            continue;
        }
        if (level == 2) {
            status = transform_record(state, &field);
        }
        else if (state->out != NULL) {
            out_tag(state->out, field.number, WIRE_LEN);
            mark = out_open(state->out, field.size, &reserved);
            status = transform_message(state, field.data, field.size, level + 1);
            out_close(state->out, mark, reserved);
        }
        else {
            status = transform_message(state, field.data, field.size, level + 1);
        }
        if (status != 0) {
            return status;
        }
    }
    if (result != 0) {
        return EINVAL;
    }

    return state->out != NULL ? state->out->error : 0;
}

int flb_opentelemetry_logs_proto_view_scan(const void *data, size_t size,
                                           const struct flb_log_view_editor *editor,
                                           size_t *records)
{
    struct transform state = {.editor = editor};
    int result;

    result = transform_message(&state, data, size, 0);
    cfl_view_destroy(&state.view);
    if (records != NULL) {
        *records = state.records;
    }

    return result;
}

int flb_opentelemetry_logs_proto_view_transform(const void *data, size_t size,
                                                const struct flb_log_view_editor *editor,
                                                void **out_buf, size_t *out_size,
                                                size_t *records, size_t *modified)
{
    struct wire_out out = {0};
    struct transform state = {.editor = editor, .out = &out};
    int result;

    *out_buf = NULL;
    *out_size = 0;
    if (out_reserve(&out, size + 64) != 0) {
        return ENOMEM;
    }

    result = transform_message(&state, data, size, 0);
    cfl_view_destroy(&state.view);
    if (records != NULL) {
        *records = state.records;
    }
    if (modified != NULL) {
        *modified = state.modified;
    }
    if (result != 0) {
        flb_free(out.data);
        return result;
    }
    *out_buf = out.data;
    *out_size = out.size;

    return 0;
}

/*
 * OTLP protobuf logs to a MessagePack log chunk
 * ---------------------------------------------
 *
 * Writes the records flb_opentelemetry_logs_protobuf_to_msgpack() produces,
 * reading the encoded request in place: no unpacked message tree and no CFL
 * objects. With an editor, the attributes of each record are loaded as a
 * view, edited and written with the edits applied.
 *
 * This reader is strict. Anything it does not take on (a repeated singular
 * message, a known field with another wire type, deep nesting, a timestamp
 * out of range, a full output) makes it return FLB_OTEL_LOGS_VIEW_FALLBACK
 * with nothing to keep, and the caller runs the unpacking decoder, which
 * stays the reference for what is accepted and what is rejected.
 */

struct mp_out {
    char *data;
    size_t size;
    size_t alloc;
    size_t limit;
    size_t added;                          /* bytes the edits of a view wrote */
    size_t removed;                        /* bytes of what the edits removed */
    int error;                             /* errno value, zero while writing */
};

static int mp_grow(struct mp_out *out, size_t extra)
{
    size_t capacity;
    char *data;

    capacity = out->alloc > 0 ? out->alloc : 8192;
    while (capacity - out->size < extra) {
        if (capacity > SIZE_MAX / 2) {
            return -1;
        }
        capacity *= 2;
    }
    data = flb_realloc(out->data, capacity);
    if (data == NULL) {
        flb_errno();
        return -1;
    }
    out->data = data;
    out->alloc = capacity;

    return 0;
}

/* Room for 'size' more bytes within the limit, or NULL with the error set. */
static FLB_INLINE uint8_t *mp_reserve(struct mp_out *out, size_t size)
{
    if (out->error != 0) {
        return NULL;
    }
    if (size > out->limit - out->size) {
        out->error = EMSGSIZE;
        return NULL;
    }
    if (out->alloc - out->size < size && mp_grow(out, size) != 0) {
        out->error = ENOMEM;
        return NULL;
    }

    return (uint8_t *) out->data + out->size;
}

static inline void mp_raw(struct mp_out *out, const void *data, size_t size)
{
    uint8_t *target;

    if (size == 0) {
        return;
    }
    target = mp_reserve(out, size);
    if (target != NULL) {
        memcpy(target, data, size);
        out->size += size;
    }
}

static inline void mp_byte(struct mp_out *out, uint8_t value)
{
    mp_raw(out, &value, 1);
}

/* big endian integer of 'width' bytes after a one byte marker */
static inline void mp_marked(struct mp_out *out, uint8_t marker, uint64_t value, int width)
{
    uint8_t *target;
    int index;

    target = mp_reserve(out, (size_t) width + 1);
    if (target == NULL) {
        return;
    }
    target[0] = marker;
    for (index = 0; index < width; index++) {
        target[width - index] = (uint8_t) (value >> (8 * index));
    }
    out->size += (size_t) width + 1;
}

/* the encodings msgpack_pack_uint64() chooses */
static void mp_uint(struct mp_out *out, uint64_t value)
{
    if (value < 128) {
        mp_byte(out, (uint8_t) value);
    }
    else if (value < 256) {
        mp_marked(out, 0xcc, value, 1);
    }
    else if (value < 65536) {
        mp_marked(out, 0xcd, value, 2);
    }
    else if (value <= UINT32_MAX) {
        mp_marked(out, 0xce, value, 4);
    }
    else {
        mp_marked(out, 0xcf, value, 8);
    }
}

/* the encodings msgpack_pack_int64() chooses */
static void mp_int(struct mp_out *out, int64_t value)
{
    if (value >= 0) {
        mp_uint(out, (uint64_t) value);
    }
    else if (value >= -32) {
        mp_byte(out, (uint8_t) value);
    }
    else if (value >= INT8_MIN) {
        mp_marked(out, 0xd0, (uint64_t) value, 1);
    }
    else if (value >= INT16_MIN) {
        mp_marked(out, 0xd1, (uint64_t) value, 2);
    }
    else if (value >= INT32_MIN) {
        mp_marked(out, 0xd2, (uint64_t) value, 4);
    }
    else {
        mp_marked(out, 0xd3, (uint64_t) value, 8);
    }
}

static void mp_double(struct mp_out *out, double value)
{
    uint64_t bits;

    memcpy(&bits, &value, sizeof(bits));
    mp_marked(out, 0xcb, bits, 8);
}

static void mp_long_str(struct mp_out *out, const char *data, size_t size)
{
    if (size < 256) {
        mp_marked(out, 0xd9, size, 1);
    }
    else if (size < 65536) {
        mp_marked(out, 0xda, size, 2);
    }
    else if (size <= UINT32_MAX) {
        mp_marked(out, 0xdb, size, 4);
    }
    else if (out->error == 0) {
        out->error = EMSGSIZE;
    }
    mp_raw(out, data, size);
}

/* Keys and most values are short: one reservation for the header and the text. */
static FLB_INLINE void mp_str(struct mp_out *out, const char *data, size_t size)
{
    uint8_t *target;

    if (size >= 32) {
        mp_long_str(out, data, size);
        return;
    }
    target = mp_reserve(out, size + 1);
    if (target != NULL) {
        target[0] = (uint8_t) (0xa0 | size);
        if (size > 0) {
            memcpy(target + 1, data, size);
        }
        out->size += size + 1;
    }
}

static FLB_INLINE void mp_key(struct mp_out *out, const char *key)
{
    mp_str(out, key, strlen(key));
}

/*
 * The unpacking decoder holds strings as C strings and measures them with
 * strlen(): what follows a NUL byte is not part of the value.
 */
static inline void mp_text(struct mp_out *out, const struct cfl_view_ref *text)
{
    mp_str(out, text->data, strnlen(text->data, text->size));
}

static void mp_bin(struct mp_out *out, const char *data, size_t size)
{
    if (size < 256) {
        mp_marked(out, 0xc4, size, 1);
    }
    else if (size < 65536) {
        mp_marked(out, 0xc5, size, 2);
    }
    else if (size <= UINT32_MAX) {
        mp_marked(out, 0xc6, size, 4);
    }
    else if (out->error == 0) {
        out->error = EMSGSIZE;
    }
    mp_raw(out, data, size);
}

static void mp_map(struct mp_out *out, size_t entries)
{
    if (entries < 16) {
        mp_byte(out, (uint8_t) (0x80 | entries));
    }
    else if (entries < 65536) {
        mp_marked(out, 0xde, entries, 2);
    }
    else if (entries <= UINT32_MAX) {
        mp_marked(out, 0xdf, entries, 4);
    }
    else if (out->error == 0) {
        out->error = EMSGSIZE;
    }
}

static void mp_array(struct mp_out *out, size_t entries)
{
    if (entries < 16) {
        mp_byte(out, (uint8_t) (0x90 | entries));
    }
    else if (entries < 65536) {
        mp_marked(out, 0xdc, entries, 2);
    }
    else if (entries <= UINT32_MAX) {
        mp_marked(out, 0xdd, entries, 4);
    }
    else if (out->error == 0) {
        out->error = EMSGSIZE;
    }
}

/* Fluent Bit v2 records, group markers included: [[EventTime, metadata], body] */
static void mp_record_header(struct mp_out *out, int64_t seconds, uint32_t nanoseconds)
{
    uint8_t header[12] = {0x92, 0x92, 0xd7, 0x00};
    uint32_t value;
    int index;

    value = (uint32_t) seconds;
    for (index = 0; index < 4; index++) {
        header[4 + index] = (uint8_t) (value >> (24 - 8 * index));
        header[8 + index] = (uint8_t) (nanoseconds >> (24 - 8 * index));
    }
    mp_raw(out, header, sizeof(header));
}

/* Key and AnyValue of an encoded KeyValue; a repeated value is not taken on. */
static int key_value_scan(const uint8_t *data, size_t size,
                          struct cfl_view_ref *key, struct cfl_view_ref *value)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    int result;

    key->data = "";
    key->size = 0;
    value->data = NULL;
    value->size = 0;
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number == 3 && field.type != WIRE_VARINT) {
            /* key_strindex, which only profiles use */
            return -1;
        }
        if (field.number != 1 && field.number != 2) {
            continue;
        }
        if (field.type != WIRE_LEN || (field.number == 2 && value->data != NULL)) {
            return -1;
        }
        if (field.number == 1) {
            key->data = (const char *) field.data;
            key->size = field.size;
        }
        else {
            value->data = (const char *) field.data;
            value->size = field.size;
        }
    }

    return result;
}

/* Number of occurrences of a repeated message field, -1 when malformed. */
static int64_t repeated_count(const uint8_t *data, size_t size, uint32_t number)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    int64_t count = 0;
    int result;

    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number == number) {
            if (field.type != WIRE_LEN) {
                return -1;
            }
            count++;
        }
    }

    return result == 0 ? count : -1;
}

static int mp_any_value(struct mp_out *out, const uint8_t *data, size_t size, int depth);

/* A repeated KeyValue field as a map: attributes and KeyValueList values. */
static int mp_key_values(struct mp_out *out, const uint8_t *data, size_t size,
                         uint32_t number, int depth)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct cfl_view_ref key;
    struct cfl_view_ref value;
    struct wire_field field;
    int64_t count;
    int result;

    count = repeated_count(data, size, number);
    if (count < 0) {
        return -1;
    }
    mp_map(out, (size_t) count);
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != number) {
            continue;
        }
        if (key_value_scan(field.data, field.size, &key, &value) != 0) {
            return -1;
        }
        mp_text(out, &key);
        if (value.data == NULL) {
            mp_byte(out, 0xc0);
        }
        else if (mp_any_value(out, (const uint8_t *) value.data, value.size, depth + 1) != 0) {
            return -1;
        }
    }

    return result;
}

/* An AnyValue, NULL for a missing one. */
static int mp_any_value(struct mp_out *out, const uint8_t *data, size_t size, int depth)
{
    static const int8_t types[9] = {-1, WIRE_LEN, WIRE_VARINT, WIRE_VARINT, WIRE_FIXED64,
                                    WIRE_LEN, WIRE_LEN, WIRE_LEN, WIRE_VARINT};
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field member = {0};
    struct wire_field field;
    const uint8_t *item;
    double real;
    int64_t count;
    int result;

    if (data == NULL) {
        mp_byte(out, 0xc0);
        return 0;
    }
    if (depth > ANY_VALUE_DEPTH) {
        return -1;
    }

    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number >= 1 && field.number <= 8) {
            if (field.type != types[field.number] || member.number != 0) {
                /*
                 * A second member replaces the first, which the unpacking
                 * decoder has parsed and validated by then: left to it.
                 */
                return -1;
            }
            member = field;
        }
    }
    if (result != 0) {
        return -1;
    }

    switch (member.number) {
    case 1:
        mp_str(out, (const char *) member.data,
               strnlen((const char *) member.data, member.size));
        break;
    case 2:
        mp_byte(out, member.value != 0 ? 0xc3 : 0xc2);
        break;
    case 3:
        mp_int(out, (int64_t) member.value);
        break;
    case 4:
        memcpy(&real, &member.value, sizeof(real));
        mp_double(out, real);
        break;
    case 5:
        count = repeated_count(member.data, member.size, 1);
        if (count < 0) {
            return -1;
        }
        mp_array(out, (size_t) count);
        item = member.data;
        end = member.data + member.size;
        while ((result = wire_next(&item, end, &field)) == 1) {
            if (field.number == 1 &&
                mp_any_value(out, field.data, field.size, depth + 1) != 0) {
                return -1;
            }
        }
        if (result != 0) {
            return -1;
        }
        break;
    case 6:
        if (mp_key_values(out, member.data, member.size, 1, depth) != 0) {
            return -1;
        }
        break;
    case 7:
        mp_bin(out, (const char *) member.data, member.size);
        break;
    default:
        /* no member, or a string table reference that only profiles use */
        mp_byte(out, 0xc0);
        break;
    }

    return 0;
}

/*
 * Upper bounds of what the decode budget charges for the request itself and
 * for one message. A log record is the largest structure of a logs request.
 */
#define PROTO_CHARGE_BASE     1024
#define PROTO_CHARGE_MESSAGE  (2 * sizeof(Opentelemetry__Proto__Logs__V1__LogRecord))

/*
 * The output limit and what a request is charged are about the records as
 * they arrive, like in the unpacking decoder, which measures them before any
 * processor runs. What an edit writes is left out of both, and what an edit
 * removes stays in.
 */
static size_t mp_edit_open(struct mp_out *out, size_t *limit)
{
    *limit = out->limit;
    out->limit = SIZE_MAX;

    return out->size;
}

static void mp_edit_close(struct mp_out *out, size_t mark, size_t limit)
{
    size_t used = out->size - mark;

    out->limit = used > SIZE_MAX - limit ? SIZE_MAX : limit + used;
    out->added += used;
}

/* Takes back what was written from 'mark' on; it stays in the charge. */
static void mp_edit_drop(struct mp_out *out, size_t mark)
{
    size_t used = out->size - mark;

    out->size = mark;
    out->limit -= used;
    out->removed += used;
}

/* A CFL object an editor placed in a view. */
static void mp_variant(struct mp_out *out, struct cfl_variant *value, int depth)
{
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_array *array;
    size_t index;

    if (value == NULL || depth > ANY_VALUE_DEPTH) {
        if (out->error == 0) {
            out->error = EINVAL;
        }
        return;
    }

    switch (value->type) {
    case CFL_VARIANT_STRING:
        mp_str(out, value->data.as_string, cfl_variant_size_get(value));
        break;
    case CFL_VARIANT_BYTES:
        mp_bin(out, value->data.as_bytes, cfl_variant_size_get(value));
        break;
    case CFL_VARIANT_BOOL:
        mp_byte(out, value->data.as_bool ? 0xc3 : 0xc2);
        break;
    case CFL_VARIANT_INT:
        mp_int(out, value->data.as_int64);
        break;
    case CFL_VARIANT_UINT:
        mp_uint(out, value->data.as_uint64);
        break;
    case CFL_VARIANT_DOUBLE:
        mp_double(out, value->data.as_double);
        break;
    case CFL_VARIANT_NULL:
        mp_byte(out, 0xc0);
        break;
    case CFL_VARIANT_ARRAY:
        array = value->data.as_array;
        mp_array(out, array != NULL ? array->entry_count : 0);
        for (index = 0; array != NULL && index < array->entry_count; index++) {
            mp_variant(out, array->entries[index], depth + 1);
        }
        break;
    case CFL_VARIANT_KVLIST:
        if (value->data.as_kvlist == NULL) {
            mp_map(out, 0);
            break;
        }
        mp_map(out, (size_t) cfl_kvlist_count(value->data.as_kvlist));
        cfl_list_foreach(head, &value->data.as_kvlist->list) {
            pair = cfl_list_entry(head, struct cfl_kvpair, _head);
            mp_str(out, pair->key, cfl_sds_len(pair->key));
            mp_variant(out, pair->val, depth + 1);
        }
        break;
    default:
        /* a reference has no record form */
        if (out->error == 0) {
            out->error = EINVAL;
        }
    }
}

struct proto_logs {
    const struct flb_opentelemetry_logs_decode_options *options;
    const struct flb_log_view_editor *editor;
    struct cfl_view view;
    struct mp_out out;
    size_t records;
    int canceled;
};

static void mp_view_literal(struct mp_out *out, const struct cfl_view_value *value)
{
    switch (value->type) {
    case CFL_VARIANT_STRING:
        mp_str(out, value->data.as_bytes.data, value->data.as_bytes.size);
        break;
    case CFL_VARIANT_BYTES:
        mp_bin(out, value->data.as_bytes.data, value->data.as_bytes.size);
        break;
    case CFL_VARIANT_BOOL:
        mp_byte(out, value->data.as_bool ? 0xc3 : 0xc2);
        break;
    case CFL_VARIANT_INT:
        mp_int(out, value->data.as_int64);
        break;
    case CFL_VARIANT_UINT:
        mp_uint(out, value->data.as_uint64);
        break;
    case CFL_VARIANT_DOUBLE:
        mp_double(out, value->data.as_double);
        break;
    case CFL_VARIANT_NULL:
        mp_byte(out, 0xc0);
        break;
    default:
        if (out->error == 0) {
            out->error = EINVAL;
        }
    }
}

/*
 * The attributes an editor took out of a record, or replaced, and the keys
 * it renamed. The values of the former were located but never read, and a
 * request with a malformed one is not accepted: they are written like the
 * others, which checks them and applies the output limit, and then dropped.
 * So is the old name of a renamed key, which the record is charged for.
 * Source entries keep the order of the record, so the ones still in the view
 * are found in one pass.
 */
static int proto_record_attributes_removed(struct proto_logs *state,
                                           const uint8_t *data, size_t size)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    const struct cfl_view_entry *entry;
    struct mp_out *out = &state->out;
    struct cfl_view_ref key;
    struct cfl_view_ref value;
    struct wire_field field;
    size_t position = 0;
    size_t count;
    size_t mark;
    int renamed;
    int result;

    count = cfl_view_count(&state->view);
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != LOG_RECORD_ATTRIBUTES) {
            continue;
        }
        renamed = FLB_FALSE;
        while (position < count &&
               cfl_view_entry_at(&state->view, position)->origin != CFL_VIEW_ENTRY_SOURCE) {
            position++;
        }
        if (position < count) {
            entry = cfl_view_entry_at(&state->view, position);
            if (entry->source.pointer == (void *) field.start) {
                position++;
                if (!entry->key_changed) {
                    continue;
                }
                renamed = FLB_TRUE;
            }
        }

        if (key_value_scan(field.data, field.size, &key, &value) != 0) {
            return -1;
        }
        mark = out->size;
        mp_text(out, &key);
        if (!renamed &&
            mp_any_value(out, (const uint8_t *) value.data, value.size, 1) != 0) {
            return -1;
        }
        if (out->error != 0) {
            return -1;
        }
        mp_edit_drop(out, mark);
    }

    return result;
}

/*
 * Attributes of a record through the view proto_record() loaded. CFL
 * processors create the attributes map when a record has none, so it is
 * always written here. A source entry keeps where its value is encoded.
 */
static int proto_record_attributes_view(struct proto_logs *state, const uint8_t *data,
                                        size_t size, size_t attributes)
{
    const struct cfl_view_entry *entry;
    struct mp_out *out = &state->out;
    struct flb_log_view log_view = {0};
    size_t sources = 0;
    size_t renamed = 0;
    size_t position;
    size_t limit;
    size_t mark;

    log_view.otel_log_attributes = &state->view;
    if (state->editor->cb_record(state->editor->data, &log_view) != 0) {
        state->canceled = FLB_TRUE;
        return -1;
    }

    if (attributes == 0) {
        /* a map the record did not have */
        mark = mp_edit_open(out, &limit);
        mp_key(out, "attributes");
        mp_map(out, cfl_view_count(&state->view));
        mp_edit_close(out, mark, limit);
    }
    else {
        /* the header of the map the record came with is what is charged */
        mp_key(out, "attributes");
        mark = out->size;
        mp_map(out, attributes);
        if (cfl_view_count(&state->view) != attributes && out->error == 0) {
            mp_edit_drop(out, mark);
            mark = mp_edit_open(out, &limit);
            mp_map(out, cfl_view_count(&state->view));
            mp_edit_close(out, mark, limit);
        }
    }
    for (position = 0; position < cfl_view_count(&state->view); position++) {
        entry = cfl_view_entry_at(&state->view, position);
        if (entry->origin == CFL_VIEW_ENTRY_SOURCE) {
            sources++;
            if (entry->key_changed) {
                renamed++;
                mark = mp_edit_open(out, &limit);
                mp_str(out, entry->key.data, entry->key.size);
                mp_edit_close(out, mark, limit);
            }
            else {
                mp_str(out, entry->key.data, entry->key.size);
            }
            if (mp_any_value(out, (const uint8_t *) entry->cache.data,
                             entry->cache.size, 1) != 0) {
                return -1;
            }
            continue;
        }

        mark = mp_edit_open(out, &limit);
        mp_str(out, entry->key.data, entry->key.size);
        if (entry->origin == CFL_VIEW_ENTRY_LITERAL) {
            mp_view_literal(out, &entry->value);
        }
        else if (entry->origin == CFL_VIEW_ENTRY_VARIANT) {
            mp_variant(out, entry->value.data.as_variant, 0);
        }
        else if (out->error == 0) {
            out->error = EINVAL;
        }
        mp_edit_close(out, mark, limit);
    }

    if (sources != attributes || renamed > 0) {
        return proto_record_attributes_removed(state, data, size);
    }

    return 0;
}

/* One LogRecord: its fields are collected first, they come in any order. */
static int proto_record(struct proto_logs *state, const uint8_t *data, size_t size)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct mp_out *out = &state->out;
    struct cfl_view_ref severity_text = {"", 0};
    struct cfl_view_ref event_name = {"", 0};
    struct cfl_view_ref trace_id = {NULL, 0};
    struct cfl_view_ref span_id = {NULL, 0};
    struct cfl_view_ref body = {NULL, 0};
    struct cfl_view_ref key;
    struct cfl_view_ref value;
    struct cfl_view_entry *entry;
    struct wire_field field;
    struct flb_time time;
    uint64_t timestamp = 0;
    uint64_t observed = 0;
    uint32_t dropped = 0;
    uint32_t flags = 0;
    int32_t severity = 0;
    size_t attributes = 0;
    size_t entries;
    int result;

    if (state->editor != NULL) {
        cfl_view_reset(&state->view, &attribute_backend, (void *) end);
    }
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        switch (field.number) {
        case 1:
        case 11:
            if (field.type != WIRE_FIXED64) {
                return -1;
            }
            if (field.number == 1) {
                timestamp = field.value;
            }
            else {
                observed = field.value;
            }
            break;
        case 2:
        case 7:
            if (field.type != WIRE_VARINT) {
                return -1;
            }
            if (field.number == 2) {
                severity = (int32_t) (uint32_t) field.value;
            }
            else {
                dropped = (uint32_t) field.value;
            }
            break;
        case 8:
            if (field.type != WIRE_FIXED32) {
                return -1;
            }
            flags = (uint32_t) field.value;
            break;
        case 3:
        case 5:
        case 6:
        case 9:
        case 10:
        case 12:
            if (field.type != WIRE_LEN) {
                return -1;
            }
            if (field.number == 3) {
                severity_text.data = (const char *) field.data;
                severity_text.size = field.size;
            }
            else if (field.number == 5) {
                if (body.data != NULL) {
                    /* a repeated body is merged by the unpacking decoder */
                    return -1;
                }
                body.data = (const char *) field.data;
                body.size = field.size;
            }
            else if (field.number == 6) {
                attributes++;
                if (state->editor != NULL) {
                    /* the view is loaded on the way, with each value located once */
                    entry = cfl_view_next_entry(&state->view);
                    if (entry == NULL ||
                        key_value_scan(field.data, field.size, &key, &value) != 0) {
                        return -1;
                    }
                    entry->key.data = key.data;
                    entry->key.size = strnlen(key.data, key.size);
                    entry->origin = CFL_VIEW_ENTRY_SOURCE;
                    entry->key_changed = FLB_FALSE;
                    entry->source.pointer = (void *) field.start;
                    entry->cache = value;
                }
            }
            else if (field.number == 9) {
                trace_id.data = (const char *) field.data;
                trace_id.size = field.size;
            }
            else if (field.number == 10) {
                span_id.data = (const char *) field.data;
                span_id.size = field.size;
            }
            else {
                event_name.data = (const char *) field.data;
                event_name.size = field.size;
            }
            break;
        default:
            break;
        }
    }
    if (result != 0) {
        return -1;
    }

    if (timestamp == 0 && observed == 0) {
        flb_time_get(&time);
    }
    else if (flb_time_from_uint64(&time, timestamp > 0 ? timestamp : observed) != 0) {
        return -1;
    }
    if (flb_time_is_valid_eventtime(&time) != FLB_TRUE) {
        return -1;
    }
    severity_text.size = strnlen(severity_text.data, severity_text.size);
    event_name.size = strnlen(event_name.data, event_name.size);

    mp_record_header(out, time.tm.tv_sec, (uint32_t) time.tm.tv_nsec);
    mp_map(out, 1);
    mp_key(out, state->options->metadata_key);

    /* trace_flags is always there */
    entries = 1 + (observed != 0) + (timestamp != 0) + (severity >= 1 && severity <= 24) +
              (severity_text.size > 0) + (state->editor != NULL || attributes > 0) +
              (dropped > 0) + (trace_id.size > 0) + (span_id.size > 0) +
              (event_name.size > 0);
    mp_map(out, entries);
    if (observed != 0) {
        mp_key(out, "observed_timestamp");
        mp_uint(out, observed);
    }
    if (timestamp != 0) {
        mp_key(out, "timestamp");
        mp_uint(out, timestamp);
    }
    if (severity >= 1 && severity <= 24) {
        mp_key(out, "severity_number");
        mp_uint(out, (uint64_t) severity);
    }
    if (severity_text.size > 0) {
        mp_key(out, "severity_text");
        mp_str(out, severity_text.data, severity_text.size);
    }
    if (state->editor != NULL) {
        if (proto_record_attributes_view(state, data, size, attributes) != 0) {
            return -1;
        }
    }
    else if (attributes > 0) {
        mp_key(out, "attributes");
        if (mp_key_values(out, data, size, LOG_RECORD_ATTRIBUTES, 0) != 0) {
            return -1;
        }
    }
    if (dropped > 0) {
        mp_key(out, "dropped_attributes_count");
        mp_uint(out, dropped);
    }
    if (trace_id.size > 0) {
        mp_key(out, "trace_id");
        mp_bin(out, trace_id.data, trace_id.size);
    }
    if (span_id.size > 0) {
        mp_key(out, "span_id");
        mp_bin(out, span_id.data, span_id.size);
    }
    mp_key(out, "trace_flags");
    mp_uint(out, flags & 0xff);
    if (event_name.size > 0) {
        mp_key(out, "event_name");
        mp_str(out, event_name.data, event_name.size);
    }

    /* a key and value list is the body itself, anything else goes under a key */
    if (state->options->body_key == NULL && body.data != NULL) {
        cursor = (const uint8_t *) body.data;
        end = cursor + body.size;
        result = 0;
        while (wire_next(&cursor, end, &field) == 1) {
            if (field.number >= 1 && field.number <= 8) {
                result = (int) field.number;
            }
        }
        if (result == 6) {
            return mp_any_value(out, (const uint8_t *) body.data, body.size, 1);
        }
    }
    mp_map(out, 1);
    mp_key(out, state->options->body_key != NULL ? state->options->body_key : "log");
    return mp_any_value(out, (const uint8_t *) body.data, body.size, 1);
}

/* The single message field 'number' of a message; a repeated one is not taken on. */
static int single_message(const uint8_t *data, size_t size, uint32_t number,
                          struct cfl_view_ref *message)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    int result;

    message->data = NULL;
    message->size = 0;
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != number) {
            continue;
        }
        if (field.type != WIRE_LEN || message->data != NULL) {
            return -1;
        }
        message->data = (const char *) field.data;
        message->size = field.size;
    }

    return result;
}

/* Last occurrence of a string or scalar field. */
static int last_field(const uint8_t *data, size_t size, uint32_t number, int type,
                      struct wire_field *found)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    struct wire_field field;
    int result;

    memset(found, 0, sizeof(*found));
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number == number) {
            if (field.type != type) {
                return -1;
            }
            *found = field;
        }
    }

    return result;
}

/* What every group of a ResourceLogs repeats, located once. */
struct proto_resource {
    struct cfl_view_ref message;
    struct wire_field schema_url;
};

static int proto_group_start(struct proto_logs *state,
                             const struct proto_resource *resource,
                             const uint8_t *scope_logs, size_t scope_size,
                             int64_t resource_index, int64_t scope_index)
{
    struct mp_out *out = &state->out;
    struct cfl_view_ref message = resource->message;
    struct wire_field schema_url = resource->schema_url;
    struct wire_field dropped;
    struct wire_field name;
    struct wire_field version;
    size_t text_size;
    size_t name_size;
    size_t version_size;
    int64_t attributes;

    mp_record_header(out, FLB_LOG_EVENT_GROUP_START, 0);
    mp_map(out, 3);
    mp_key(out, "schema");
    mp_key(out, "otlp");
    mp_key(out, "resource_id");
    mp_int(out, resource_index);
    mp_key(out, "scope_id");
    mp_int(out, scope_index);

    mp_map(out, 2);
    mp_key(out, "resource");
    if (message.data == NULL) {
        mp_map(out, 0);
    }
    else {
        attributes = repeated_count((const uint8_t *) message.data, message.size, 1);
        if (attributes < 0 ||
            last_field((const uint8_t *) message.data, message.size, 2, WIRE_VARINT,
                       &dropped) != 0 ||
            repeated_count((const uint8_t *) message.data, message.size, 3) != 0) {
            /* entity references included: they are not read here */
            return -1;
        }
        /* the schema URL of a resource is written even when it is empty */
        mp_map(out, 1 + (attributes > 0) + ((uint32_t) dropped.value > 0));
        if (attributes > 0) {
            mp_key(out, "attributes");
            if (mp_key_values(out, (const uint8_t *) message.data, message.size, 1, 0) != 0) {
                return -1;
            }
        }
        if ((uint32_t) dropped.value > 0) {
            mp_key(out, "dropped_attributes_count");
            mp_uint(out, (uint32_t) dropped.value);
        }
        mp_key(out, "schema_url");
        mp_str(out, (const char *) schema_url.data,
               schema_url.data != NULL ? strnlen((const char *) schema_url.data,
                                                 schema_url.size) : 0);
    }

    mp_key(out, "scope");
    if (single_message(scope_logs, scope_size, 1, &message) != 0 ||
        last_field(scope_logs, scope_size, 3, WIRE_LEN, &schema_url) != 0) {
        return -1;
    }
    text_size = schema_url.data != NULL ? strnlen((const char *) schema_url.data,
                                                  schema_url.size) : 0;
    if (message.data == NULL) {
        mp_map(out, text_size > 0);
        if (text_size > 0) {
            mp_key(out, "schema_url");
            mp_str(out, (const char *) schema_url.data, text_size);
        }
        return 0;
    }

    attributes = repeated_count((const uint8_t *) message.data, message.size, 3);
    if (attributes < 0 ||
        last_field((const uint8_t *) message.data, message.size, 1, WIRE_LEN, &name) != 0 ||
        last_field((const uint8_t *) message.data, message.size, 2, WIRE_LEN, &version) != 0 ||
        last_field((const uint8_t *) message.data, message.size, 4, WIRE_VARINT,
                   &dropped) != 0) {
        return -1;
    }
    name_size = name.data != NULL ? strnlen((const char *) name.data, name.size) : 0;
    version_size = version.data != NULL ? strnlen((const char *) version.data,
                                                  version.size) : 0;
    mp_map(out, (text_size > 0) + (name_size > 0) + (version_size > 0) + (attributes > 0) +
                ((uint32_t) dropped.value > 0));
    if (text_size > 0) {
        mp_key(out, "schema_url");
        mp_str(out, (const char *) schema_url.data, text_size);
    }
    if (name_size > 0) {
        mp_key(out, "name");
        mp_str(out, (const char *) name.data, name_size);
    }
    if (version_size > 0) {
        mp_key(out, "version");
        mp_str(out, (const char *) version.data, version_size);
    }
    if (attributes > 0) {
        mp_key(out, "attributes");
        if (mp_key_values(out, (const uint8_t *) message.data, message.size, 3, 0) != 0) {
            return -1;
        }
    }
    if ((uint32_t) dropped.value > 0) {
        mp_key(out, "dropped_attributes_count");
        mp_uint(out, (uint32_t) dropped.value);
    }

    return 0;
}

static int proto_resource_logs(struct proto_logs *state, const uint8_t *data, size_t size,
                               int64_t resource_index)
{
    const uint8_t *cursor = data;
    const uint8_t *end = data + size;
    const uint8_t *record;
    const uint8_t *scope_end;
    struct proto_resource resource;
    struct wire_field scope;
    struct wire_field field;
    int64_t scope_index = -1;
    int64_t records;
    int result;

    if (single_message(data, size, 1, &resource.message) != 0 ||
        last_field(data, size, 3, WIRE_LEN, &resource.schema_url) != 0) {
        return -1;
    }

    while ((result = wire_next(&cursor, end, &scope)) == 1) {
        if (scope.number != 2) {
            continue;
        }
        if (scope.type != WIRE_LEN) {
            return -1;
        }
        scope_index++;
        records = repeated_count(scope.data, scope.size, 2);
        if (records < 0) {
            return -1;
        }
        if (records == 0) {
            /*
             * A scope without records opens no group, but its content still
             * decides whether the request is valid: not checked here.
             */
            return -1;
        }
        if (proto_group_start(state, &resource, scope.data, scope.size, resource_index,
                              scope_index) != 0) {
            return -1;
        }
        record = scope.data;
        scope_end = scope.data + scope.size;
        while ((result = wire_next(&record, scope_end, &field)) == 1) {
            if (field.number != 2) {
                continue;
            }
            if (proto_record(state, field.data, field.size) != 0) {
                return -1;
            }
            state->records++;
        }
        if (result != 0) {
            return -1;
        }
        mp_record_header(&state->out, FLB_LOG_EVENT_GROUP_END, 0);
        mp_map(&state->out, 0);
        mp_map(&state->out, 0);
    }
    if (result == 0 && scope_index < 0) {
        /* resource logs without a scope: same as a scope without records */
        return -1;
    }

    return result;
}

int flb_opentelemetry_logs_proto_view_within_budget(size_t size, size_t budget)
{
    return budget >= PROTO_CHARGE_BASE &&
           size <= (budget - PROTO_CHARGE_BASE) / (1 + (128 + PROTO_CHARGE_MESSAGE) / 2);
}

int flb_opentelemetry_logs_proto_view_to_msgpack(
        const void *payload, size_t size,
        const struct flb_opentelemetry_logs_decode_options *options,
        const struct flb_log_view_editor *editor,
        struct flb_opentelemetry_log_buffer *output)
{
    const uint8_t *cursor = payload;
    const uint8_t *end = cursor + size;
    struct proto_logs state = {.options = options, .editor = editor};
    struct wire_field field;
    int64_t resource_index = 0;
    size_t budget;
    int result;

    output->size = 0;
    output->charged = 0;
    output->records = 0;
    if (options == NULL || options->metadata_key == NULL || (payload == NULL && size != 0)) {
        return FLB_OTEL_LOGS_VIEW_FALLBACK;
    }

    /*
     * The unpacking decoder validates a request against a decode budget
     * before it allocates anything: the request size, 128 bytes per field
     * and the structure of every message. Nothing is allocated here, but a
     * limit the user set keeps its meaning, so both reject the same
     * requests. A field takes two bytes or more, which bounds what a request
     * can be charged; only one that could reach the budget needs that pass.
     * Its structural rules are the ones this reader applies as it goes.
     */
    budget = options->protobuf_decode_max_size;
    if (budget == 0) {
        budget = FLB_OTEL_PROTOBUF_DECODE_BUDGET;
    }
    if (!flb_opentelemetry_logs_proto_view_within_budget(size, budget)) {
        if (flb_opentelemetry_protobuf_validate_with_budget(
                &opentelemetry__proto__collector__logs__v1__export_logs_service_request__descriptor,
                payload, size, &budget) != 0) {
            return FLB_OTEL_LOGS_VIEW_FALLBACK;
        }
    }

    state.out.data = output->data;
    state.out.alloc = output->capacity;
    state.out.limit = options->output_limit;
    /*
     * The records take about as much room as the request. One allocation up
     * front replaces a series of growing ones, each with its copy.
     */
    result = 0;
    if (size > 0 && state.out.alloc < size + size / 4 && size + size / 4 <= state.out.limit) {
        result = mp_grow(&state.out, size + size / 4);
    }
    if (result != 0) {
        return FLB_OTEL_LOGS_VIEW_FALLBACK;
    }
    while ((result = wire_next(&cursor, end, &field)) == 1) {
        if (field.number != 1) {
            continue;
        }
        if (field.type != WIRE_LEN ||
            proto_resource_logs(&state, field.data, field.size, resource_index) != 0) {
            result = -1;
            break;
        }
        resource_index++;
    }
    cfl_view_destroy(&state.view);

    /* the buffer may have moved while it grew */
    output->data = state.out.data;
    output->capacity = state.out.alloc;
    if (state.canceled) {
        return FLB_OTEL_LOGS_VIEW_CANCELED;
    }
    if (result != 0 || state.out.error != 0) {
        return FLB_OTEL_LOGS_VIEW_FALLBACK;
    }
    output->size = state.out.size;
    output->charged = state.out.size - state.out.added + state.out.removed;
    output->records = state.records;

    return 0;
}
