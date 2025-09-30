/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CMetrics
 *  ========
 *  Copyright 2021-2022 The CMetrics Authors
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

#ifndef VARIANT_UTILS_H
#define VARIANT_UTILS_H

#include <mpack/mpack.h>

/* These are the only functions meant for general use,
 * the reason why the kvlist packing and unpacking
 * functions are exposed is the internal and external
 * metadata kvlists in the cmetrics context are not
 * contained by a variant instance.
 *
 * Result :
 * Upon success all of these return 0, otherwise they will
 * raise the innermost error code which should be treated
 * as an opaque value.
 *
 * Notes :
 * When decoding -1 means the check after mpack_read_tag
 * failed and -2 means the type was not the one expected
 */

static inline int pack_cfl_variant(mpack_writer_t *writer,
                                   struct cfl_variant *value);

static inline int pack_cfl_variant_kvlist(mpack_writer_t *writer,
                                          struct cfl_kvlist *kvlist);

static inline int unpack_cfl_variant(mpack_reader_t *reader,
                                     struct cfl_variant **value);

static inline int unpack_cfl_kvlist(mpack_reader_t *reader,
                                    struct cfl_kvlist **result_kvlist);

/* Packers */
static inline int pack_cfl_variant_string(mpack_writer_t *writer,
                                          char *value)
{
    mpack_write_cstr(writer, value);

    return 0;
}

static inline int pack_cfl_variant_binary(mpack_writer_t *writer,
                                          char *value,
                                          size_t length)
{
    mpack_write_bin(writer, value, length);

    return 0;
}

static inline int pack_cfl_variant_boolean(mpack_writer_t *writer,
                                           unsigned int value)
{
    mpack_write_bool(writer, value);

    return 0;
}

static inline int pack_cfl_variant_int64(mpack_writer_t *writer,
                                         int64_t value)
{
    mpack_write_int(writer, value);

    return 0;
}

static inline int pack_cfl_variant_double(mpack_writer_t *writer,
                                          double value)
{
    mpack_write_double(writer, value);

    return 0;
}

static inline int pack_cfl_variant_array(mpack_writer_t *writer,
                                         struct cfl_array *array)
{
    size_t              entry_count;
    struct cfl_variant *entry_value;
    int                 result;
    size_t              index;

    entry_count = array->entry_count;

    mpack_start_array(writer, entry_count);

    for (index = 0 ; index < entry_count ; index++) {
        entry_value = cfl_array_fetch_by_index(array, index);

        if (entry_value == NULL) {
            return -1;
        }

        result = pack_cfl_variant(writer, entry_value);

        if (result != 0) {
            return result;
        }
    }

    mpack_finish_array(writer);

    return 0;
}

static inline int pack_cfl_variant_kvlist(mpack_writer_t *writer,
                                          struct cfl_kvlist *kvlist) {
    size_t             entry_count;
    struct cfl_list   *iterator;
    struct cfl_kvpair *kvpair;
    int                result;

    entry_count = cfl_kvlist_count(kvlist);

    mpack_start_map(writer, entry_count);

    cfl_list_foreach(iterator, &kvlist->list) {
        kvpair = cfl_list_entry(iterator, struct cfl_kvpair, _head);

        mpack_write_cstr(writer, kvpair->key);

        result = pack_cfl_variant(writer, kvpair->val);

        if (result != 0) {
            return result;
        }
    }

    mpack_finish_map(writer);

    return 0;
}

static inline int pack_cfl_variant(mpack_writer_t *writer,
                                   struct cfl_variant *value)
{
    int result;

    if (value->type == CFL_VARIANT_STRING) {
        result = pack_cfl_variant_string(writer, value->data.as_string);
    }
    else if (value->type == CFL_VARIANT_BOOL) {
        result = pack_cfl_variant_boolean(writer, value->data.as_bool);
    }
    else if (value->type == CFL_VARIANT_INT) {
        result = pack_cfl_variant_int64(writer, value->data.as_int64);
    }
    else if (value->type == CFL_VARIANT_DOUBLE) {
        result = pack_cfl_variant_double(writer, value->data.as_double);
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        result = pack_cfl_variant_array(writer, value->data.as_array);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        result = pack_cfl_variant_kvlist(writer, value->data.as_kvlist);
    }
    else if (value->type == CFL_VARIANT_BYTES) {
        result = pack_cfl_variant_binary(writer,
                                         value->data.as_bytes,
                                         cfl_sds_len(value->data.as_bytes));
    }
    else if (value->type == CFL_VARIANT_REFERENCE) {
        result = pack_cfl_variant_string(writer, value->data.as_string);
    }
    else {
        result = -1;
    }

    return result;
}

/* Unpackers */

static inline int unpack_cfl_variant_read_tag(mpack_reader_t *reader,
                                              mpack_tag_t *tag,
                                              mpack_type_t expected_type)
{
    *tag = mpack_read_tag(reader);

    if (mpack_ok != mpack_reader_error(reader)) {
        return -1;
    }

    if (mpack_tag_type(tag) != expected_type) {
        return -2;
    }

    return 0;
}

static inline int unpack_cfl_array(mpack_reader_t *reader,
                                   struct cfl_array **result_array)
{
    struct cfl_array   *internal_array;
    size_t              entry_count;
    struct cfl_variant *entry_value;
    int                 result;
    size_t              index;
    mpack_tag_t         tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_array);

    if (result != 0) {
        return result;
    }

    entry_count = mpack_tag_array_count(&tag);

    internal_array = cfl_array_create(entry_count);

    if (internal_array == NULL) {
        return -3;
    }

    for (index = 0 ; index < entry_count ; index++) {
        result = unpack_cfl_variant(reader, &entry_value);

        if (result != 0) {
            cfl_array_destroy(internal_array);

            return -4;
        }

        result = cfl_array_append(internal_array, entry_value);

        if (result != 0) {
            cfl_array_destroy(internal_array);

            return -5;
        }
    }

    mpack_done_array(reader);

    if (mpack_reader_error(reader) != mpack_ok) {
        cfl_array_destroy(internal_array);

        return -6;
    }

    *result_array = internal_array;

    return 0;
}

static inline int unpack_cfl_kvlist(mpack_reader_t *reader,
                                    struct cfl_kvlist **result_kvlist)
{
    struct cfl_kvlist   *internal_kvlist;
    char                 key_name[256];
    size_t               entry_count;
    size_t               key_length;
    struct cfl_variant  *key_value;
    mpack_tag_t          key_tag;
    int                  result;
    size_t               index;
    mpack_tag_t          tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_map);

    if (result != 0) {
        return result;
    }

    entry_count = mpack_tag_map_count(&tag);

    internal_kvlist = cfl_kvlist_create();

    if (internal_kvlist == NULL) {
        return -3;
    }

    result = 0;
    key_value = NULL;

    for (index = 0 ; index < entry_count ; index++) {
        result = unpack_cfl_variant_read_tag(reader, &key_tag, mpack_type_str);

        if (result != 0) {
            result = -4;

            break;
        }

        key_length = mpack_tag_str_length(&key_tag);

        if (key_length >= sizeof(key_name)) {
            result = -5;

            break;
        }

        mpack_read_cstr(reader, key_name, sizeof(key_name), key_length);

        key_name[key_length] = '\0';

        mpack_done_str(reader);

        if (mpack_ok != mpack_reader_error(reader)) {
            result = -6;

            break;
        }

        result = unpack_cfl_variant(reader, &key_value);

        if (result != 0) {
            result = -7;

            break;
        }

        result = cfl_kvlist_insert(internal_kvlist, key_name, key_value);

        if (result != 0) {
            result = -8;

            break;
        }

        key_value = NULL;
    }

    mpack_done_map(reader);

    if (mpack_reader_error(reader) != mpack_ok) {
        result = -9;
    }

    if (result != 0) {
        cfl_kvlist_destroy(internal_kvlist);

        if (key_value != NULL) {
            cfl_variant_destroy(key_value);
        }
    }
    else {
        *result_kvlist = internal_kvlist;
    }

    return result;
}

static inline int unpack_cfl_variant_string(mpack_reader_t *reader,
                                            struct cfl_variant **value)
{
    size_t      value_length;
    char       *value_data;
    int         result;
    mpack_tag_t tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_str);

    if (result != 0) {
        return result;
    }

    value_length = mpack_tag_str_length(&tag);

    value_data = cfl_sds_create_size(value_length + 1);

    if (value_data == NULL) {
        return -3;
    }

    cfl_sds_set_len(value_data, value_length);

    mpack_read_cstr(reader, value_data, value_length + 1, value_length);

    mpack_done_str(reader);

    if (mpack_reader_error(reader) != mpack_ok) {
        cfl_sds_destroy(value_data);

        return -4;
    }

    *value = cfl_variant_create_from_reference(value_data);

    if (*value == NULL) {
        return -5;
    }

    (*value)->type = CFL_VARIANT_STRING;

    return 0;
}

static inline int unpack_cfl_variant_binary(mpack_reader_t *reader,
                                            struct cfl_variant **value)
{
    size_t      value_length;
    char       *value_data;
    int         result;
    mpack_tag_t tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_bin);

    if (result != 0) {
        return result;
    }

    value_length = mpack_tag_bin_length(&tag);

    value_data = cfl_sds_create_size(value_length);

    if (value_data == NULL) {
        return -3;
    }

    cfl_sds_set_len(value_data, value_length);

    mpack_read_bytes(reader, value_data, value_length);

    mpack_done_bin(reader);

    if (mpack_reader_error(reader) != mpack_ok) {
        cfl_sds_destroy(value_data);

        return -4;
    }

    *value = cfl_variant_create_from_reference(value_data);

    if (*value == NULL) {
        return -5;
    }

    (*value)->type = CFL_VARIANT_BYTES;

    return 0;
}

static inline int unpack_cfl_variant_boolean(mpack_reader_t *reader,
                                             struct cfl_variant **value)
{
    int         result;
    mpack_tag_t tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_bool);

    if (result != 0) {
        return result;
    }

    *value = cfl_variant_create_from_bool((unsigned int) mpack_tag_bool_value(&tag));

    if (*value == NULL) {
        return -3;
    }

    return 0;
}

static inline int unpack_cfl_variant_uint64(mpack_reader_t *reader,
                                            struct cfl_variant **value)
{
    int         result;
    mpack_tag_t tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_uint);

    if (result != 0) {
        return result;
    }

    *value = cfl_variant_create_from_int64((int64_t) mpack_tag_uint_value(&tag));

    if (*value == NULL) {
        return -3;
    }

    return 0;
}

static inline int unpack_cfl_variant_int64(mpack_reader_t *reader,
                                           struct cfl_variant **value)
{
    int         result;
    mpack_tag_t tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_int);

    if (result != 0) {
        return result;
    }

    *value = cfl_variant_create_from_int64((int64_t) mpack_tag_int_value(&tag));

    if (*value == NULL) {
        return -3;
    }

    return 0;
}

static inline int unpack_cfl_variant_double(mpack_reader_t *reader,
                                            struct cfl_variant **value)
{
    int         result;
    mpack_tag_t tag;

    result = unpack_cfl_variant_read_tag(reader, &tag, mpack_type_double);

    if (result != 0) {
        return result;
    }

    *value = cfl_variant_create_from_double(mpack_tag_double_value(&tag));

    if (*value == NULL) {
        return -3;
    }

    return 0;
}

static inline int unpack_cfl_variant_array(mpack_reader_t *reader,
                                           struct cfl_variant **value)
{
    struct cfl_array *unpacked_array;
    int               result;

    result = unpack_cfl_array(reader, &unpacked_array);

    if (result != 0) {
        return result;
    }

    *value = cfl_variant_create_from_array(unpacked_array);

    if (*value == NULL) {
        return -3;
    }

    return 0;
}

static inline int unpack_cfl_variant_kvlist(mpack_reader_t *reader,
                                            struct cfl_variant **value)
{
    struct cfl_kvlist *unpacked_kvlist;
    int                result;

    result = unpack_cfl_kvlist(reader, &unpacked_kvlist);

    if (result != 0) {
        return result;
    }

    *value = cfl_variant_create_from_kvlist(unpacked_kvlist);

    if (*value == NULL) {
        return -3;
    }

    return 0;
}

static inline int unpack_cfl_variant(mpack_reader_t *reader,
                                     struct cfl_variant **value)
{
    mpack_type_t value_type;
    int          result;
    mpack_tag_t  tag;

    tag = mpack_peek_tag(reader);

    if (mpack_ok != mpack_reader_error(reader)) {
        return -1;
    }

    value_type = mpack_tag_type(&tag);

    if (value_type == mpack_type_str) {
        result = unpack_cfl_variant_string(reader, value);
    }
    else if (value_type == mpack_type_bool) {
        result = unpack_cfl_variant_boolean(reader, value);
    }
    else if (value_type == mpack_type_int) {
        result = unpack_cfl_variant_int64(reader, value);
    }
    else if (value_type == mpack_type_uint) {
        result = unpack_cfl_variant_uint64(reader, value);
    }
    else if (value_type == mpack_type_double) {
        result = unpack_cfl_variant_double(reader, value);
    }
    else if (value_type == mpack_type_array) {
        result = unpack_cfl_variant_array(reader, value);
    }
    else if (value_type == mpack_type_map) {
        result = unpack_cfl_variant_kvlist(reader, value);
    }
    else if (value_type == mpack_type_bin) {
        result = unpack_cfl_variant_binary(reader, value);
    }
    else {
        result = -1;
    }

    return result;
}

cfl_sds_t cfl_variant_convert_to_json(struct cfl_variant *value);
int cfl_variant_convert(struct cfl_variant *input_value,
                        struct cfl_variant **output_value,
                        int output_type);


int cm_utils_hash_transformer(void *context, struct cfl_variant *value);
cfl_sds_t cm_utils_variant_convert_to_json(struct cfl_variant *value);
int cm_utils_variant_convert(struct cfl_variant *input_value,
                             struct cfl_variant **output_value,
                             int output_type);

#endif
