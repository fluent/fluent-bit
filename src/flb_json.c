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

#include <fluent-bit/flb_json.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <msgpack.h>
#ifdef FLB_HAVE_YYJSON
#include <yyjson.h>
#endif

enum flb_json_mut_type {
    FLB_JSON_MUT_OBJECT,
    FLB_JSON_MUT_ARRAY,
    FLB_JSON_MUT_STRING,
    FLB_JSON_MUT_BOOL,
    FLB_JSON_MUT_INT,
    FLB_JSON_MUT_UINT,
    FLB_JSON_MUT_REAL,
    FLB_JSON_MUT_NULL
};

struct flb_json_doc;
struct flb_json_mut_doc;

struct flb_json_val {
    struct flb_json_doc *owner;
    msgpack_object      *object;
    struct flb_json_val *next;
};

struct flb_json_doc {
    char                *buffer;
    size_t               buffer_size;
    msgpack_unpacked     unpacked;
    struct flb_json_val  root;
    struct flb_json_val *wrappers;
};

struct flb_json_mut_kv {
    flb_sds_t                key;
    struct flb_json_mut_val *value;
    struct flb_json_mut_kv  *next;
    struct flb_json_mut_kv  *alloc_next;
};

struct flb_json_mut_entry {
    struct flb_json_mut_val   *value;
    struct flb_json_mut_entry *next;
    struct flb_json_mut_entry *alloc_next;
};

struct flb_json_mut_val {
    enum flb_json_mut_type type;
    struct flb_json_mut_doc *owner;

    union {
        struct {
            struct flb_json_mut_kv *head;
            struct flb_json_mut_kv *tail;
        } object;

        struct {
            struct flb_json_mut_entry *head;
            struct flb_json_mut_entry *tail;
            size_t                     count;
        } array;

        flb_sds_t           string;
        int                 boolean;
        long long           sint;
        unsigned long long  uint;
        double              real;
    } data;

    struct flb_json_mut_val *next;
};

struct flb_json_mut_doc {
    struct flb_json_mut_val   *root;
    struct flb_json_mut_val   *values;
    struct flb_json_mut_kv    *kvs;
    struct flb_json_mut_entry *entries;
};

#ifdef FLB_HAVE_YYJSON
static void *flb_json_yyjson_malloc(void *ctx, size_t size)
{
    (void) ctx;

    return flb_malloc(size);
}

static void *flb_json_yyjson_realloc(void *ctx, void *ptr,
                                     size_t old_size, size_t size)
{
    (void) ctx;
    (void) old_size;

    return flb_realloc(ptr, size);
}

static void flb_json_yyjson_free(void *ctx, void *ptr)
{
    (void) ctx;

    flb_free(ptr);
}

static void flb_json_yyjson_init_alc(yyjson_alc *allocator)
{
    allocator->malloc = flb_json_yyjson_malloc;
    allocator->realloc = flb_json_yyjson_realloc;
    allocator->free = flb_json_yyjson_free;
    allocator->ctx = NULL;
}
#endif

static struct flb_json_val *parsed_value_wrap(struct flb_json_doc *doc,
                                              msgpack_object *object)
{
    struct flb_json_val *wrapper;

    wrapper = flb_calloc(1, sizeof(struct flb_json_val));
    if (wrapper == NULL) {
        flb_errno();
        return NULL;
    }

    wrapper->owner = doc;
    wrapper->object = object;
    wrapper->next = doc->wrappers;
    doc->wrappers = wrapper;

    return wrapper;
}

static int json_append_indent(flb_sds_t *buffer, size_t depth, size_t spaces)
{
    size_t index;

    for (index = 0; index < depth * spaces; index++) {
        *buffer = flb_sds_cat(*buffer, " ", 1);
        if (*buffer == NULL) {
            return -1;
        }
    }

    return 0;
}

static int json_append_escaped_string(flb_sds_t *buffer,
                                      const char *value,
                                      size_t length)
{
    static const char hex[] = "0123456789abcdef";
    size_t            index;
    char              escaped[6];
    unsigned char     c;

    *buffer = flb_sds_cat(*buffer, "\"", 1);
    if (*buffer == NULL) {
        return -1;
    }

    for (index = 0; index < length; index++) {
        c = (unsigned char) value[index];

        if (c == '"' || c == '\\') {
            escaped[0] = '\\';
            escaped[1] = (char) c;

            *buffer = flb_sds_cat(*buffer, escaped, 2);
        }
        else if (c == '\b') {
            *buffer = flb_sds_cat(*buffer, "\\b", 2);
        }
        else if (c == '\f') {
            *buffer = flb_sds_cat(*buffer, "\\f", 2);
        }
        else if (c == '\n') {
            *buffer = flb_sds_cat(*buffer, "\\n", 2);
        }
        else if (c == '\r') {
            *buffer = flb_sds_cat(*buffer, "\\r", 2);
        }
        else if (c == '\t') {
            *buffer = flb_sds_cat(*buffer, "\\t", 2);
        }
        else if (c < 0x20) {
            escaped[0] = '\\';
            escaped[1] = 'u';
            escaped[2] = '0';
            escaped[3] = '0';
            escaped[4] = hex[(c >> 4) & 0x0f];
            escaped[5] = hex[c & 0x0f];

            *buffer = flb_sds_cat(*buffer, escaped, sizeof(escaped));
        }
        else {
            *buffer = flb_sds_cat(*buffer, (const char *) &value[index], 1);
        }

        if (*buffer == NULL) {
            return -1;
        }
    }

    *buffer = flb_sds_cat(*buffer, "\"", 1);
    if (*buffer == NULL) {
        return -1;
    }

    return 0;
}

static int render_msgpack_object(flb_sds_t *buffer,
                                 msgpack_object *object,
                                 int pretty,
                                 size_t depth);

static int render_msgpack_map(flb_sds_t *buffer,
                              msgpack_object_map *map,
                              int pretty,
                              size_t depth)
{
    size_t          index;
    msgpack_object *key;
    msgpack_object *value;

    *buffer = flb_sds_cat(*buffer, "{", 1);
    if (*buffer == NULL) {
        return -1;
    }

    if (map->size == 0) {
        *buffer = flb_sds_cat(*buffer, "}", 1);
        return (*buffer == NULL) ? -1 : 0;
    }

    for (index = 0; index < map->size; index++) {
        key = &map->ptr[index].key;
        value = &map->ptr[index].val;

        if (pretty) {
            *buffer = flb_sds_cat(*buffer, "\n", 1);
            if (*buffer == NULL || json_append_indent(buffer, depth + 1, 2) != 0) {
                return -1;
            }
        }
        if (key->type != MSGPACK_OBJECT_STR ||
            json_append_escaped_string(buffer,
                                       key->via.str.ptr,
                                       key->via.str.size) != 0) {
            return -1;
        }

        *buffer = flb_sds_cat(*buffer, pretty ? ": " : ":", pretty ? 2 : 1);
        if (*buffer == NULL) {
            return -1;
        }

        if (render_msgpack_object(buffer, value, pretty, depth + 1) != 0) {
            return -1;
        }

        if (index + 1 < map->size) {
            *buffer = flb_sds_cat(*buffer, ",", 1);
            if (*buffer == NULL) {
                return -1;
            }
        }
    }

    if (pretty) {
        *buffer = flb_sds_cat(*buffer, "\n", 1);
        if (*buffer == NULL || json_append_indent(buffer, depth, 2) != 0) {
            return -1;
        }
    }

    *buffer = flb_sds_cat(*buffer, "}", 1);
    return (*buffer == NULL) ? -1 : 0;
}

static int render_msgpack_array(flb_sds_t *buffer,
                                msgpack_object_array *array,
                                int pretty,
                                size_t depth)
{
    size_t index;

    *buffer = flb_sds_cat(*buffer, "[", 1);
    if (*buffer == NULL) {
        return -1;
    }

    if (array->size == 0) {
        *buffer = flb_sds_cat(*buffer, "]", 1);
        return (*buffer == NULL) ? -1 : 0;
    }

    for (index = 0; index < array->size; index++) {
        if (pretty) {
            *buffer = flb_sds_cat(*buffer, "\n", 1);
            if (*buffer == NULL || json_append_indent(buffer, depth + 1, 2) != 0) {
                return -1;
            }
        }
        if (render_msgpack_object(buffer, &array->ptr[index], pretty, depth + 1) != 0) {
            return -1;
        }

        if (index + 1 < array->size) {
            *buffer = flb_sds_cat(*buffer, ",", 1);
            if (*buffer == NULL) {
                return -1;
            }
        }
    }

    if (pretty) {
        *buffer = flb_sds_cat(*buffer, "\n", 1);
        if (*buffer == NULL || json_append_indent(buffer, depth, 2) != 0) {
            return -1;
        }
    }

    *buffer = flb_sds_cat(*buffer, "]", 1);
    return (*buffer == NULL) ? -1 : 0;
}

static int render_msgpack_object(flb_sds_t *buffer,
                                 msgpack_object *object,
                                 int pretty,
                                 size_t depth)
{
    char tmp[64];
    int  length;

    switch (object->type) {
    case MSGPACK_OBJECT_NIL:
        *buffer = flb_sds_cat(*buffer, "null", 4);
        return (*buffer == NULL) ? -1 : 0;
    case MSGPACK_OBJECT_BOOLEAN:
        *buffer = flb_sds_cat(*buffer,
                              object->via.boolean ? "true" : "false",
                              object->via.boolean ? 4 : 5);
        return (*buffer == NULL) ? -1 : 0;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        length = snprintf(tmp, sizeof(tmp), "%" PRIu64, object->via.u64);
        break;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        length = snprintf(tmp, sizeof(tmp), "%" PRId64, object->via.i64);
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        length = snprintf(tmp, sizeof(tmp), "%.17g", object->via.f64);
        break;
    case MSGPACK_OBJECT_STR:
        return json_append_escaped_string(buffer,
                                          object->via.str.ptr,
                                          object->via.str.size);
    case MSGPACK_OBJECT_ARRAY:
        return render_msgpack_array(buffer, &object->via.array, pretty, depth);
    case MSGPACK_OBJECT_MAP:
        return render_msgpack_map(buffer, &object->via.map, pretty, depth);
    default:
        return -1;
    }

    if (length <= 0 || (size_t) length >= sizeof(tmp)) {
        return -1;
    }

    *buffer = flb_sds_cat(*buffer, tmp, length);
    return (*buffer == NULL) ? -1 : 0;
}

static char *render_msgpack_document(struct flb_json_doc *document,
                                     size_t *length,
                                     int pretty)
{
    flb_sds_t buffer;
    char     *output;
    size_t    size;

    buffer = flb_sds_create_size(512);
    if (buffer == NULL) {
        flb_errno();
        return NULL;
    }

    if (render_msgpack_object(&buffer, document->root.object, pretty, 0) != 0) {
        flb_sds_destroy(buffer);
        return NULL;
    }

    size = flb_sds_len(buffer);
    output = flb_malloc(size + 1);
    if (output == NULL) {
        flb_errno();
        flb_sds_destroy(buffer);
        return NULL;
    }

    memcpy(output, buffer, size);
    output[size] = '\0';
    flb_sds_destroy(buffer);

    if (length != NULL) {
        *length = size;
    }

    return output;
}

#ifdef FLB_HAVE_YYJSON
static yyjson_mut_val *msgpack_to_yyjson_mut(yyjson_mut_doc *document,
                                             msgpack_object *object)
{
    size_t          index;
    yyjson_mut_val *result;
    yyjson_mut_val *value;
    msgpack_object *key;

    switch (object->type) {
    case MSGPACK_OBJECT_NIL:
        return yyjson_mut_null(document);
    case MSGPACK_OBJECT_BOOLEAN:
        return yyjson_mut_bool(document, object->via.boolean);
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        return yyjson_mut_uint(document, object->via.u64);
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        return yyjson_mut_sint(document, object->via.i64);
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        return yyjson_mut_real(document, object->via.f64);
    case MSGPACK_OBJECT_STR:
        return yyjson_mut_strncpy(document,
                                  object->via.str.ptr,
                                  object->via.str.size);
    case MSGPACK_OBJECT_ARRAY:
        result = yyjson_mut_arr(document);
        if (result == NULL) {
            return NULL;
        }

        for (index = 0; index < object->via.array.size; index++) {
            value = msgpack_to_yyjson_mut(document, &object->via.array.ptr[index]);
            if (value == NULL || !yyjson_mut_arr_add_val(result, value)) {
                return NULL;
            }
        }

        return result;
    case MSGPACK_OBJECT_MAP:
        result = yyjson_mut_obj(document);
        if (result == NULL) {
            return NULL;
        }

        for (index = 0; index < object->via.map.size; index++) {
            key = &object->via.map.ptr[index].key;
            value = msgpack_to_yyjson_mut(document, &object->via.map.ptr[index].val);

            if (key->type != MSGPACK_OBJECT_STR || value == NULL) {
                return NULL;
            }

            if (!yyjson_mut_obj_add(result,
                                    yyjson_mut_strncpy(document,
                                                       key->via.str.ptr,
                                                       key->via.str.size),
                                    value)) {
                return NULL;
            }
        }

        return result;
    default:
        return NULL;
    }
}

static yyjson_mut_val *mutable_to_yyjson_mut(yyjson_mut_doc *document,
                                             struct flb_json_mut_val *value)
{
    struct flb_json_mut_kv    *kv_entry;
    struct flb_json_mut_entry *array_entry;
    yyjson_mut_val            *result;
    yyjson_mut_val            *item;

    switch (value->type) {
    case FLB_JSON_MUT_OBJECT:
        result = yyjson_mut_obj(document);
        if (result == NULL) {
            return NULL;
        }

        for (kv_entry = value->data.object.head;
             kv_entry != NULL;
             kv_entry = kv_entry->next) {
            item = mutable_to_yyjson_mut(document, kv_entry->value);
            if (item == NULL) {
                return NULL;
            }

            if (!yyjson_mut_obj_add(result,
                                    yyjson_mut_strcpy(document, kv_entry->key),
                                    item)) {
                return NULL;
            }
        }

        return result;
    case FLB_JSON_MUT_ARRAY:
        result = yyjson_mut_arr(document);
        if (result == NULL) {
            return NULL;
        }

        for (array_entry = value->data.array.head;
             array_entry != NULL;
             array_entry = array_entry->next) {
            item = mutable_to_yyjson_mut(document, array_entry->value);
            if (item == NULL || !yyjson_mut_arr_add_val(result, item)) {
                return NULL;
            }
        }

        return result;
    case FLB_JSON_MUT_STRING:
        return yyjson_mut_strcpy(document, value->data.string);
    case FLB_JSON_MUT_BOOL:
        return yyjson_mut_bool(document, value->data.boolean);
    case FLB_JSON_MUT_INT:
        return yyjson_mut_sint(document, value->data.sint);
    case FLB_JSON_MUT_UINT:
        return yyjson_mut_uint(document, value->data.uint);
    case FLB_JSON_MUT_REAL:
        return yyjson_mut_real(document, value->data.real);
    case FLB_JSON_MUT_NULL:
        return yyjson_mut_null(document);
    default:
        return NULL;
    }
}

static char *render_msgpack_document_yyjson(struct flb_json_doc *document,
                                            size_t *length,
                                            int pretty)
{
    yyjson_alc      allocator;
    yyjson_mut_doc *yy_document;
    yyjson_mut_val *root;
    yyjson_write_flag flags;
    char           *output;

    flb_json_yyjson_init_alc(&allocator);

    yy_document = yyjson_mut_doc_new(&allocator);
    if (yy_document == NULL) {
        return NULL;
    }

    root = msgpack_to_yyjson_mut(yy_document, document->root.object);
    if (root == NULL) {
        yyjson_mut_doc_free(yy_document);
        return NULL;
    }

    yyjson_mut_doc_set_root(yy_document, root);

    flags = 0;
    if (pretty) {
        flags |= YYJSON_WRITE_PRETTY_TWO_SPACES;
    }

    output = yyjson_mut_write_opts(yy_document, flags, &allocator, length, NULL);
    yyjson_mut_doc_free(yy_document);

    return output;
}

static char *render_mutable_document_yyjson(struct flb_json_mut_doc *document,
                                            size_t *length,
                                            int pretty)
{
    yyjson_alc      allocator;
    yyjson_mut_doc *yy_document;
    yyjson_mut_val *root;
    yyjson_write_flag flags;
    char           *output;

    if (document == NULL || document->root == NULL) {
        return NULL;
    }

    flb_json_yyjson_init_alc(&allocator);

    yy_document = yyjson_mut_doc_new(&allocator);
    if (yy_document == NULL) {
        return NULL;
    }

    root = mutable_to_yyjson_mut(yy_document, document->root);
    if (root == NULL) {
        yyjson_mut_doc_free(yy_document);
        return NULL;
    }

    yyjson_mut_doc_set_root(yy_document, root);

    flags = 0;
    if (pretty) {
        flags |= YYJSON_WRITE_PRETTY_TWO_SPACES;
    }

    output = yyjson_mut_write_opts(yy_document, flags, &allocator, length, NULL);
    yyjson_mut_doc_free(yy_document);

    return output;
}
#endif

static struct flb_json_mut_val *mut_value_create(struct flb_json_mut_doc *document,
                                                 enum flb_json_mut_type type)
{
    struct flb_json_mut_val *value;

    value = flb_calloc(1, sizeof(struct flb_json_mut_val));
    if (value == NULL) {
        flb_errno();
        return NULL;
    }

    value->type = type;
    value->owner = document;
    value->next = document->values;
    document->values = value;

    return value;
}

static struct flb_json_mut_kv *mut_kv_create(struct flb_json_mut_doc *document,
                                             const char *key,
                                             size_t key_length,
                                             struct flb_json_mut_val *value)
{
    struct flb_json_mut_kv *entry;

    entry = flb_calloc(1, sizeof(struct flb_json_mut_kv));
    if (entry == NULL) {
        flb_errno();
        return NULL;
    }

    entry->key = flb_sds_create_len(key, key_length);
    if (entry->key == NULL) {
        flb_free(entry);
        return NULL;
    }

    entry->value = value;
    entry->alloc_next = document->kvs;
    document->kvs = entry;

    return entry;
}

static struct flb_json_mut_entry *mut_array_entry_create(struct flb_json_mut_doc *document,
                                                         struct flb_json_mut_val *value)
{
    struct flb_json_mut_entry *entry;

    entry = flb_calloc(1, sizeof(struct flb_json_mut_entry));
    if (entry == NULL) {
        flb_errno();
        return NULL;
    }

    entry->value = value;
    entry->alloc_next = document->entries;
    document->entries = entry;

    return entry;
}

static struct flb_json_mut_val *copy_msgpack_to_mutable(struct flb_json_mut_doc *document,
                                                        msgpack_object *object);

static int flb_json_mut_obj_add_val_len(struct flb_json_mut_doc *document,
                                        struct flb_json_mut_val *object,
                                        const char *key,
                                        size_t key_length,
                                        struct flb_json_mut_val *value);

static struct flb_json_mut_val *copy_msgpack_array_to_mutable(struct flb_json_mut_doc *document,
                                                              msgpack_object_array *array)
{
    size_t                   index;
    struct flb_json_mut_val *result;
    struct flb_json_mut_val *value;

    result = mut_value_create(document, FLB_JSON_MUT_ARRAY);
    if (result == NULL) {
        return NULL;
    }

    for (index = 0; index < array->size; index++) {
        value = copy_msgpack_to_mutable(document, &array->ptr[index]);
        if (value == NULL || !flb_json_mut_arr_add_val(result, value)) {
            return NULL;
        }
    }

    return result;
}

static struct flb_json_mut_val *copy_msgpack_map_to_mutable(struct flb_json_mut_doc *document,
                                                            msgpack_object_map *map)
{
    size_t                   index;
    msgpack_object          *key;
    struct flb_json_mut_val *result;
    struct flb_json_mut_val *value;

    result = mut_value_create(document, FLB_JSON_MUT_OBJECT);
    if (result == NULL) {
        return NULL;
    }

    for (index = 0; index < map->size; index++) {
        key = &map->ptr[index].key;
        value = copy_msgpack_to_mutable(document, &map->ptr[index].val);

        if (key->type != MSGPACK_OBJECT_STR || value == NULL ||
            !flb_json_mut_obj_add_val_len(document,
                                          result,
                                          key->via.str.ptr,
                                          key->via.str.size,
                                          value)) {
            return NULL;
        }
    }

    return result;
}

static struct flb_json_mut_val *copy_msgpack_to_mutable(struct flb_json_mut_doc *document,
                                                        msgpack_object *object)
{
    struct flb_json_mut_val *value;

    switch (object->type) {
    case MSGPACK_OBJECT_MAP:
        return copy_msgpack_map_to_mutable(document, &object->via.map);
    case MSGPACK_OBJECT_ARRAY:
        return copy_msgpack_array_to_mutable(document, &object->via.array);
    case MSGPACK_OBJECT_STR:
        value = mut_value_create(document, FLB_JSON_MUT_STRING);
        if (value == NULL) {
            return NULL;
        }

        value->data.string = flb_sds_create_len(object->via.str.ptr,
                                                object->via.str.size);
        return (value->data.string != NULL) ? value : NULL;
    case MSGPACK_OBJECT_BOOLEAN:
        value = mut_value_create(document, FLB_JSON_MUT_BOOL);
        if (value != NULL) {
            value->data.boolean = object->via.boolean;
        }
        return value;
    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        value = mut_value_create(document, FLB_JSON_MUT_UINT);
        if (value != NULL) {
            value->data.uint = object->via.u64;
        }
        return value;
    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        value = mut_value_create(document, FLB_JSON_MUT_INT);
        if (value != NULL) {
            value->data.sint = object->via.i64;
        }
        return value;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        value = mut_value_create(document, FLB_JSON_MUT_REAL);
        if (value != NULL) {
            value->data.real = object->via.f64;
        }
        return value;
    case MSGPACK_OBJECT_NIL:
        return mut_value_create(document, FLB_JSON_MUT_NULL);
    default:
        return NULL;
    }
}

static int render_mutable_value(flb_sds_t *buffer,
                                struct flb_json_mut_val *value,
                                int pretty,
                                size_t depth);

static int render_mutable_object(flb_sds_t *buffer,
                                 struct flb_json_mut_val *value,
                                 int pretty,
                                 size_t depth)
{
    int                     first;
    struct flb_json_mut_kv *entry;

    *buffer = flb_sds_cat(*buffer, "{", 1);
    if (*buffer == NULL) {
        return -1;
    }

    if (value->data.object.head == NULL) {
        *buffer = flb_sds_cat(*buffer, "}", 1);
        return (*buffer == NULL) ? -1 : 0;
    }

    first = FLB_TRUE;

    for (entry = value->data.object.head; entry != NULL; entry = entry->next) {
        if (!first) {
            *buffer = flb_sds_cat(*buffer, ",", 1);
            if (*buffer == NULL) {
                return -1;
            }
        }

        if (pretty) {
            *buffer = flb_sds_cat(*buffer, "\n", 1);
            if (*buffer == NULL || json_append_indent(buffer, depth + 1, 2) != 0) {
                return -1;
            }
        }

        if (json_append_escaped_string(buffer, entry->key, flb_sds_len(entry->key)) != 0) {
            return -1;
        }

        *buffer = flb_sds_cat(*buffer, pretty ? ": " : ":", pretty ? 2 : 1);
        if (*buffer == NULL ||
            render_mutable_value(buffer, entry->value, pretty, depth + 1) != 0) {
            return -1;
        }

        first = FLB_FALSE;
    }

    if (pretty) {
        *buffer = flb_sds_cat(*buffer, "\n", 1);
        if (*buffer == NULL || json_append_indent(buffer, depth, 2) != 0) {
            return -1;
        }
    }

    *buffer = flb_sds_cat(*buffer, "}", 1);
    return (*buffer == NULL) ? -1 : 0;
}

static int render_mutable_array(flb_sds_t *buffer,
                                struct flb_json_mut_val *value,
                                int pretty,
                                size_t depth)
{
    int                        first;
    struct flb_json_mut_entry *entry;

    *buffer = flb_sds_cat(*buffer, "[", 1);
    if (*buffer == NULL) {
        return -1;
    }

    if (value->data.array.head == NULL) {
        *buffer = flb_sds_cat(*buffer, "]", 1);
        return (*buffer == NULL) ? -1 : 0;
    }

    first = FLB_TRUE;

    for (entry = value->data.array.head; entry != NULL; entry = entry->next) {
        if (!first) {
            *buffer = flb_sds_cat(*buffer, ",", 1);
            if (*buffer == NULL) {
                return -1;
            }
        }

        if (pretty) {
            *buffer = flb_sds_cat(*buffer, "\n", 1);
            if (*buffer == NULL || json_append_indent(buffer, depth + 1, 2) != 0) {
                return -1;
            }
        }

        if (render_mutable_value(buffer, entry->value, pretty, depth + 1) != 0) {
            return -1;
        }

        first = FLB_FALSE;
    }

    if (pretty) {
        *buffer = flb_sds_cat(*buffer, "\n", 1);
        if (*buffer == NULL || json_append_indent(buffer, depth, 2) != 0) {
            return -1;
        }
    }

    *buffer = flb_sds_cat(*buffer, "]", 1);
    return (*buffer == NULL) ? -1 : 0;
}

static int render_mutable_value(flb_sds_t *buffer,
                                struct flb_json_mut_val *value,
                                int pretty,
                                size_t depth)
{
    char tmp[64];
    int  length;

    switch (value->type) {
    case FLB_JSON_MUT_OBJECT:
        return render_mutable_object(buffer, value, pretty, depth);
    case FLB_JSON_MUT_ARRAY:
        return render_mutable_array(buffer, value, pretty, depth);
    case FLB_JSON_MUT_STRING:
        return json_append_escaped_string(buffer,
                                          value->data.string,
                                          flb_sds_len(value->data.string));
    case FLB_JSON_MUT_BOOL:
        *buffer = flb_sds_cat(*buffer,
                              value->data.boolean ? "true" : "false",
                              value->data.boolean ? 4 : 5);
        return (*buffer == NULL) ? -1 : 0;
    case FLB_JSON_MUT_INT:
        length = snprintf(tmp, sizeof(tmp), "%lld", value->data.sint);
        break;
    case FLB_JSON_MUT_UINT:
        length = snprintf(tmp, sizeof(tmp), "%llu", value->data.uint);
        break;
    case FLB_JSON_MUT_REAL:
        length = snprintf(tmp, sizeof(tmp), "%.17g", value->data.real);
        break;
    case FLB_JSON_MUT_NULL:
        *buffer = flb_sds_cat(*buffer, "null", 4);
        return (*buffer == NULL) ? -1 : 0;
    default:
        return -1;
    }

    if (length <= 0 || (size_t) length >= sizeof(tmp)) {
        return -1;
    }

    *buffer = flb_sds_cat(*buffer, tmp, length);
    return (*buffer == NULL) ? -1 : 0;
}

static char *render_mutable_document(struct flb_json_mut_doc *document,
                                     size_t *length,
                                     int pretty)
{
    flb_sds_t buffer;
    char     *output;
    size_t    size;

    if (document == NULL || document->root == NULL) {
        return NULL;
    }

    buffer = flb_sds_create_size(512);
    if (buffer == NULL) {
        flb_errno();
        return NULL;
    }

    if (render_mutable_value(&buffer, document->root, pretty, 0) != 0) {
        flb_sds_destroy(buffer);
        return NULL;
    }

    size = flb_sds_len(buffer);
    output = flb_malloc(size + 1);
    if (output == NULL) {
        flb_errno();
        flb_sds_destroy(buffer);
        return NULL;
    }

    memcpy(output, buffer, size);
    output[size] = '\0';
    flb_sds_destroy(buffer);

    if (length != NULL) {
        *length = size;
    }

    return output;
}

struct flb_json_doc *flb_json_read(const char *input, size_t length)
{
    int                  root_type;
    char                *buffer;
    size_t               buffer_size;
    size_t               offset;
    struct flb_json_doc *document;

    buffer = NULL;
    buffer_size = 0;
    offset = 0;

    if (flb_pack_json(input, length, &buffer, &buffer_size, &root_type, NULL) != 0) {
        return NULL;
    }

    document = flb_calloc(1, sizeof(struct flb_json_doc));
    if (document == NULL) {
        flb_errno();
        flb_free(buffer);
        return NULL;
    }

    document->buffer = buffer;
    document->buffer_size = buffer_size;
    msgpack_unpacked_init(&document->unpacked);

    if (msgpack_unpack_next(&document->unpacked, buffer, buffer_size, &offset) !=
        MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&document->unpacked);
        flb_free(buffer);
        flb_free(document);
        return NULL;
    }

    document->root.owner = document;
    document->root.object = &document->unpacked.data;

    return document;
}

void flb_json_doc_destroy(struct flb_json_doc *document)
{
    struct flb_json_val *wrapper;
    struct flb_json_val *tmp;

    if (document == NULL) {
        return;
    }

    wrapper = document->wrappers;
    while (wrapper != NULL) {
        tmp = wrapper->next;
        flb_free(wrapper);
        wrapper = tmp;
    }

    msgpack_unpacked_destroy(&document->unpacked);
    flb_free(document->buffer);
    flb_free(document);
}

struct flb_json_val *flb_json_doc_get_root(struct flb_json_doc *document)
{
    return (document != NULL) ? &document->root : NULL;
}

char *flb_json_write(struct flb_json_doc *document, size_t *length)
{
#ifdef FLB_HAVE_YYJSON
    char *output;
#endif

    if (document == NULL || document->root.object == NULL) {
        return NULL;
    }

#ifdef FLB_HAVE_YYJSON
    output = render_msgpack_document_yyjson(document, length, FLB_FALSE);
    if (output != NULL) {
        return output;
    }
#endif

    return render_msgpack_document(document, length, FLB_FALSE);
}

char *flb_json_write_pretty(struct flb_json_doc *document, size_t *length)
{
#ifdef FLB_HAVE_YYJSON
    char *output;
#endif

    if (document == NULL || document->root.object == NULL) {
        return NULL;
    }

#ifdef FLB_HAVE_YYJSON
    output = render_msgpack_document_yyjson(document, length, FLB_TRUE);
    if (output != NULL) {
        return output;
    }
#endif

    return render_msgpack_document(document, length, FLB_TRUE);
}

char *flb_json_prettify(const char *input, size_t input_length, size_t *length)
{
#ifdef FLB_HAVE_YYJSON
    yyjson_alc        allocator;
    yyjson_doc       *document;
    yyjson_read_err   read_error;
    yyjson_write_flag flags;
    char             *output;

    if (input == NULL) {
        return NULL;
    }

    flb_json_yyjson_init_alc(&allocator);

    document = yyjson_read_opts((char *) input, input_length, 0,
                                &allocator, &read_error);
    if (document != NULL) {
        flags = YYJSON_WRITE_PRETTY_TWO_SPACES;
        output = yyjson_write_opts(document, flags, &allocator, length, NULL);
        yyjson_doc_free(document);

        if (output != NULL) {
            return output;
        }
    }
#endif
    int       escape_next;
    int       in_string;
    char      current;
    char      next;
    char      last_token;
    flb_sds_t buffer;
    size_t    depth;
    size_t    index;
    size_t    lookahead;

    if (input == NULL) {
        return NULL;
    }

    buffer = flb_sds_create_size(input_length + 32);
    if (buffer == NULL) {
        return NULL;
    }

    depth = 0;
    in_string = FLB_FALSE;
    escape_next = FLB_FALSE;
    last_token = '\0';

    for (index = 0; index < input_length; index++) {
        current = input[index];

        if (in_string == FLB_TRUE) {
            buffer = flb_sds_cat(buffer, &current, 1);
            if (buffer == NULL) {
                return NULL;
            }

            if (escape_next == FLB_TRUE) {
                escape_next = FLB_FALSE;
            }
            else if (current == '\\') {
                escape_next = FLB_TRUE;
            }
            else if (current == '"') {
                in_string = FLB_FALSE;
            }

            continue;
        }

        if (current == ' ' || current == '\n' ||
            current == '\r' || current == '\t') {
            continue;
        }

        if (current == '"') {
            in_string = FLB_TRUE;
            buffer = flb_sds_cat(buffer, &current, 1);
            if (buffer == NULL) {
                return NULL;
            }
            continue;
        }

        if (current == '{' || current == '[') {
            buffer = flb_sds_cat(buffer, &current, 1);
            if (buffer == NULL) {
                return NULL;
            }

            next = '\0';
            for (lookahead = index + 1; lookahead < input_length; lookahead++) {
                next = input[lookahead];
                if (next != ' ' && next != '\n' &&
                    next != '\r' && next != '\t') {
                    break;
                }
            }

            depth++;

            if (!((current == '{' && next == '}') ||
                  (current == '[' && next == ']'))) {
                buffer = flb_sds_cat(buffer, "\n", 1);
                if (buffer == NULL || json_append_indent(&buffer, depth, 2) != 0) {
                    return NULL;
                }
            }

            last_token = current;
            continue;
        }

        if (current == '}' || current == ']') {
            if (depth > 0) {
                depth--;
            }

            if (last_token != '{' && last_token != '[') {
                buffer = flb_sds_cat(buffer, "\n", 1);
                if (buffer == NULL || json_append_indent(&buffer, depth, 2) != 0) {
                    return NULL;
                }
            }

            buffer = flb_sds_cat(buffer, &current, 1);
            if (buffer == NULL) {
                return NULL;
            }

            last_token = current;
            continue;
        }

        if (current == ',') {
            buffer = flb_sds_cat(buffer, ",\n", 2);
            if (buffer == NULL || json_append_indent(&buffer, depth, 2) != 0) {
                return NULL;
            }

            last_token = current;
            continue;
        }

        if (current == ':') {
            buffer = flb_sds_cat(buffer, ": ", 2);
            if (buffer == NULL) {
                return NULL;
            }

            last_token = current;
            continue;
        }

        buffer = flb_sds_cat(buffer, &current, 1);
        if (buffer == NULL) {
            return NULL;
        }

        last_token = current;
    }

    if (length != NULL) {
        *length = flb_sds_len(buffer);
    }

    return buffer;
}

struct flb_json_val *flb_json_obj_get(struct flb_json_val *value, const char *key)
{
    size_t          index;
    msgpack_object *entry_key;

    if (value == NULL || key == NULL || value->object == NULL ||
        value->object->type != MSGPACK_OBJECT_MAP) {
        return NULL;
    }

    for (index = 0; index < value->object->via.map.size; index++) {
        entry_key = &value->object->via.map.ptr[index].key;

        if (entry_key->type == MSGPACK_OBJECT_STR &&
            entry_key->via.str.size == strlen(key) &&
            strncmp(entry_key->via.str.ptr, key, entry_key->via.str.size) == 0) {
            return parsed_value_wrap(value->owner,
                                     &value->object->via.map.ptr[index].val);
        }
    }

    return NULL;
}

size_t flb_json_arr_size(struct flb_json_val *value)
{
    if (value == NULL || value->object == NULL ||
        value->object->type != MSGPACK_OBJECT_ARRAY) {
        return 0;
    }

    return value->object->via.array.size;
}

struct flb_json_val *flb_json_arr_get(struct flb_json_val *value, size_t index)
{
    if (value == NULL || value->object == NULL ||
        value->object->type != MSGPACK_OBJECT_ARRAY ||
        index >= value->object->via.array.size) {
        return NULL;
    }

    return parsed_value_wrap(value->owner, &value->object->via.array.ptr[index]);
}

struct flb_json_mut_doc *flb_json_mut_doc_create(void)
{
    struct flb_json_mut_doc *document;

    document = flb_calloc(1, sizeof(struct flb_json_mut_doc));
    if (document == NULL) {
        flb_errno();
    }

    return document;
}

void flb_json_mut_doc_destroy(struct flb_json_mut_doc *document)
{
    struct flb_json_mut_val   *value;
    struct flb_json_mut_val   *next_value;
    struct flb_json_mut_kv    *kv;
    struct flb_json_mut_kv    *next_kv;
    struct flb_json_mut_entry *entry;
    struct flb_json_mut_entry *next_entry;

    if (document == NULL) {
        return;
    }

    value = document->values;
    while (value != NULL) {
        next_value = value->next;

        if (value->type == FLB_JSON_MUT_STRING && value->data.string != NULL) {
            flb_sds_destroy(value->data.string);
        }

        flb_free(value);
        value = next_value;
    }

    kv = document->kvs;
    while (kv != NULL) {
        next_kv = kv->alloc_next;
        flb_sds_destroy(kv->key);
        flb_free(kv);
        kv = next_kv;
    }

    entry = document->entries;
    while (entry != NULL) {
        next_entry = entry->alloc_next;
        flb_free(entry);
        entry = next_entry;
    }

    flb_free(document);
}

void flb_json_mut_doc_set_root(struct flb_json_mut_doc *document,
                               struct flb_json_mut_val *root)
{
    if (document == NULL) {
        return;
    }

    if (root != NULL && root->owner != document) {
        return;
    }

    document->root = root;
}

char *flb_json_mut_write(struct flb_json_mut_doc *document, size_t *length)
{
#ifdef FLB_HAVE_YYJSON
    char *output;

    output = render_mutable_document_yyjson(document, length, FLB_FALSE);
    if (output != NULL) {
        return output;
    }
#endif

    return render_mutable_document(document, length, FLB_FALSE);
}

char *flb_json_mut_write_pretty(struct flb_json_mut_doc *document, size_t *length)
{
#ifdef FLB_HAVE_YYJSON
    char *output;

    output = render_mutable_document_yyjson(document, length, FLB_TRUE);
    if (output != NULL) {
        return output;
    }
#endif

    return render_mutable_document(document, length, FLB_TRUE);
}

struct flb_json_mut_val *flb_json_mut_obj(struct flb_json_mut_doc *document)
{
    return (document != NULL) ? mut_value_create(document, FLB_JSON_MUT_OBJECT) : NULL;
}

struct flb_json_mut_val *flb_json_mut_arr(struct flb_json_mut_doc *document)
{
    return (document != NULL) ? mut_value_create(document, FLB_JSON_MUT_ARRAY) : NULL;
}

struct flb_json_mut_val *flb_json_mut_strncpy(struct flb_json_mut_doc *document,
                                              const char *value,
                                              size_t length)
{
    struct flb_json_mut_val *result;

    if (document == NULL || value == NULL) {
        return NULL;
    }

    result = mut_value_create(document, FLB_JSON_MUT_STRING);
    if (result == NULL) {
        return NULL;
    }

    result->data.string = flb_sds_create_len(value, length);
    if (result->data.string == NULL) {
        return NULL;
    }

    return result;
}

struct flb_json_mut_val *flb_json_val_mut_copy(struct flb_json_mut_doc *target,
                                               struct flb_json_val *source)
{
    if (target == NULL || source == NULL || source->object == NULL) {
        return NULL;
    }

    return copy_msgpack_to_mutable(target, source->object);
}

int flb_json_mut_arr_add_real(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *array,
                              double value)
{
    struct flb_json_mut_val *entry;

    if (document == NULL || array == NULL ||
        array->type != FLB_JSON_MUT_ARRAY) {
        return 0;
    }

    entry = mut_value_create(document, FLB_JSON_MUT_REAL);
    if (entry == NULL) {
        return 0;
    }

    entry->data.real = value;

    return flb_json_mut_arr_add_val(array, entry);
}

int flb_json_mut_arr_add_strncpy(struct flb_json_mut_doc *document,
                                 struct flb_json_mut_val *array,
                                 const char *value,
                                 size_t length)
{
    struct flb_json_mut_val *entry;

    if (document == NULL || array == NULL ||
        array->type != FLB_JSON_MUT_ARRAY) {
        return 0;
    }

    entry = flb_json_mut_strncpy(document, value, length);
    if (entry == NULL) {
        return 0;
    }

    return flb_json_mut_arr_add_val(array, entry);
}

int flb_json_mut_arr_add_val(struct flb_json_mut_val *array,
                             struct flb_json_mut_val *value)
{
    struct flb_json_mut_entry *entry;

    if (array == NULL || value == NULL || array->type != FLB_JSON_MUT_ARRAY) {
        return 0;
    }

    if (array->owner == NULL || value->owner != array->owner) {
        return 0;
    }

    entry = mut_array_entry_create(array->owner, value);
    if (entry == NULL) {
        return 0;
    }

    if (array->data.array.tail != NULL) {
        array->data.array.tail->next = entry;
    }
    else {
        array->data.array.head = entry;
    }

    array->data.array.tail = entry;
    array->data.array.count++;

    return 1;
}

size_t flb_json_mut_arr_size(struct flb_json_mut_val *array)
{
    if (array == NULL || array->type != FLB_JSON_MUT_ARRAY) {
        return 0;
    }

    return array->data.array.count;
}

int flb_json_mut_obj_add_bool(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              int value)
{
    struct flb_json_mut_val *entry;

    if (document == NULL || object == NULL || key == NULL) {
        return 0;
    }

    entry = mut_value_create(document, FLB_JSON_MUT_BOOL);
    if (entry == NULL) {
        return 0;
    }

    entry->data.boolean = value;

    return flb_json_mut_obj_add_val(document, object, key, entry);
}

int flb_json_mut_obj_add_int(struct flb_json_mut_doc *document,
                             struct flb_json_mut_val *object,
                             const char *key,
                             long long value)
{
    struct flb_json_mut_val *entry;

    if (document == NULL || object == NULL || key == NULL) {
        return 0;
    }

    entry = mut_value_create(document, FLB_JSON_MUT_INT);
    if (entry == NULL) {
        return 0;
    }

    entry->data.sint = value;

    return flb_json_mut_obj_add_val(document, object, key, entry);
}

int flb_json_mut_obj_add_real(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              double value)
{
    struct flb_json_mut_val *entry;

    if (document == NULL || object == NULL || key == NULL) {
        return 0;
    }

    entry = mut_value_create(document, FLB_JSON_MUT_REAL);
    if (entry == NULL) {
        return 0;
    }

    entry->data.real = value;

    return flb_json_mut_obj_add_val(document, object, key, entry);
}

int flb_json_mut_obj_add_str(struct flb_json_mut_doc *document,
                             struct flb_json_mut_val *object,
                             const char *key,
                             const char *value)
{
    if (document == NULL || object == NULL || key == NULL || value == NULL) {
        return 0;
    }

    return flb_json_mut_obj_add_strncpy(document, object,
                                        key, value, strlen(value));
}

int flb_json_mut_obj_add_strcpy(struct flb_json_mut_doc *document,
                                struct flb_json_mut_val *object,
                                const char *key,
                                const char *value)
{
    return flb_json_mut_obj_add_str(document, object, key, value);
}

int flb_json_mut_obj_add_strn(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              const char *value,
                              size_t length)
{
    return flb_json_mut_obj_add_strncpy(document, object, key, value, length);
}

int flb_json_mut_obj_add_strncpy(struct flb_json_mut_doc *document,
                                 struct flb_json_mut_val *object,
                                 const char *key,
                                 const char *value,
                                 size_t length)
{
    struct flb_json_mut_val *entry;

    if (document == NULL || object == NULL ||
        key == NULL || value == NULL ||
        object->type != FLB_JSON_MUT_OBJECT) {
        return 0;
    }

    entry = flb_json_mut_strncpy(document, value, length);
    if (entry == NULL) {
        return 0;
    }

    return flb_json_mut_obj_add_val(document, object, key, entry);
}

int flb_json_mut_obj_add_uint(struct flb_json_mut_doc *document,
                              struct flb_json_mut_val *object,
                              const char *key,
                              unsigned long long value)
{
    struct flb_json_mut_val *entry;

    if (document == NULL || object == NULL || key == NULL) {
        return 0;
    }

    entry = mut_value_create(document, FLB_JSON_MUT_UINT);
    if (entry == NULL) {
        return 0;
    }

    entry->data.uint = value;

    return flb_json_mut_obj_add_val(document, object, key, entry);
}

static int flb_json_mut_obj_add_val_len(struct flb_json_mut_doc *document,
                                        struct flb_json_mut_val *object,
                                        const char *key,
                                        size_t key_length,
                                        struct flb_json_mut_val *value)
{
    struct flb_json_mut_kv *entry;

    if (document == NULL || object == NULL || key == NULL || value == NULL ||
        object->type != FLB_JSON_MUT_OBJECT) {
        return 0;
    }

    if (object->owner != document || value->owner != document) {
        return 0;
    }

    entry = mut_kv_create(document, key, key_length, value);
    if (entry == NULL) {
        return 0;
    }

    if (object->data.object.tail != NULL) {
        object->data.object.tail->next = entry;
    }
    else {
        object->data.object.head = entry;
    }

    object->data.object.tail = entry;

    return 1;
}

int flb_json_mut_obj_add_val(struct flb_json_mut_doc *document,
                             struct flb_json_mut_val *object,
                             const char *key,
                             struct flb_json_mut_val *value)
{
    if (key == NULL) {
        return 0;
    }

    return flb_json_mut_obj_add_val_len(document, object, key,
                                        strlen(key), value);
}
