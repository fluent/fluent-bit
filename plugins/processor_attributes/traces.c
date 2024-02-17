/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_processor.h>
#include <cfl/cfl.h>

#include "variant_utils.h"

typedef int (*attribute_transformer) (void *, struct cfl_variant *value);

static int span_contains_attribute(struct ctrace_span *span,
                                   char *name)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    return cfl_kvlist_contains(span->attr->kv, name);
}

static int span_remove_attribute(struct ctrace_span *span,
                                 char *name)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    return cfl_kvlist_remove(span->attr->kv, name);
}

static int span_update_attribute(struct ctrace_span *span,
                                 char *name,
                                 char *value)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    cfl_kvlist_remove(span->attr->kv, name);

    if (ctr_span_set_attribute_string(span, name, value) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int span_insert_attribute(struct ctrace_span *span,
                                 char *name,
                                 char *value)
{
    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    if (ctr_span_set_attribute_string(span, name, value) != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int span_transform_attribute(struct ctrace_span *span,
                                    char *name,
                                    attribute_transformer transformer)
{
    struct cfl_variant *attribute;

    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    attribute = cfl_kvlist_fetch(span->attr->kv, name);

    if (attribute == NULL) {
        return FLB_FALSE;
    }

    return transformer(NULL, attribute);
}

static int span_convert_attribute(struct ctrace_span *span,
                                  char *name,
                                  char *new_type)
{
    struct cfl_variant *converted_attribute;
    int                 new_type_constant;
    struct cfl_variant *attribute;
    int                 result;

    if (strcasecmp(new_type, "string") == 0 ||
        strcasecmp(new_type, "str") == 0) {
        new_type_constant = CFL_VARIANT_STRING;
    }
    else if (strcasecmp(new_type, "bytes") == 0) {
        new_type_constant = CFL_VARIANT_BYTES;
    }
    else if (strcasecmp(new_type, "boolean") == 0 ||
             strcasecmp(new_type, "bool") == 0) {
        new_type_constant = CFL_VARIANT_BOOL;
    }
    else if (strcasecmp(new_type, "integer") == 0 ||
             strcasecmp(new_type, "int64") == 0 ||
             strcasecmp(new_type, "int") == 0) {
        new_type_constant = CFL_VARIANT_INT;
    }
    else if (strcasecmp(new_type, "double") == 0 ||
             strcasecmp(new_type, "dbl") == 0) {
        new_type_constant = CFL_VARIANT_DOUBLE;
    }
    else if (strcasecmp(new_type, "array") == 0) {
        new_type_constant = CFL_VARIANT_ARRAY;
    }
    else {
        return FLB_FALSE;
    }

    if (span->attr == NULL) {
        return FLB_FALSE;
    }

    attribute = cfl_kvlist_fetch(span->attr->kv, name);

    if (attribute == NULL) {
        return FLB_FALSE;
    }

    result = cfl_variant_convert(attribute,
                                 &converted_attribute,
                                 new_type_constant);

    if (result != FLB_TRUE) {
        return FLB_FALSE;
    }

    result = cfl_kvlist_remove(span->attr->kv, name);

    if (result != FLB_TRUE) {
        return FLB_FALSE;
    }


    result = cfl_kvlist_insert(span->attr->kv, name, converted_attribute);

    if (result != 0) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static void attribute_match_cb(const char *name,
                               const char *value,
                               size_t value_length,
                               void *context)
{
    cfl_sds_t           temporary_value;
    struct ctrace_span *span;

    temporary_value = cfl_sds_create_len(value, value_length);

    if (temporary_value != NULL) {
        span = (struct ctrace_span *) context;

        if (span_contains_attribute(span, (char *) name) == FLB_TRUE) {
            span_remove_attribute(span, (char *) name);
        }

        ctr_span_set_attribute_string(span, (char *) name, temporary_value);

        cfl_sds_destroy(temporary_value);
    }
}

static int span_extract_attributes(struct ctrace_span *span,
                                   char *name,
                                   char *pattern)
{
    ssize_t                  match_count;
    struct flb_regex_search  match_list;
    struct cfl_variant      *attribute;
    int                      result;
    struct flb_regex        *regex;

    regex = flb_regex_create(pattern);

    if (regex == NULL) {
        return FLB_FALSE;
    }

    attribute = cfl_kvlist_fetch(span->attr->kv, name);

    if (attribute == NULL) {
        flb_regex_destroy(regex);

        return FLB_FALSE;
    }


    if (attribute->type != CFL_VARIANT_STRING) {
        flb_regex_destroy(regex);

        return FLB_FALSE;
    }

    match_count = flb_regex_do(regex,
                               attribute->data.as_string,
                               cfl_sds_len(attribute->data.as_string),
                               &match_list);

    if (match_count <= 0) {
        flb_regex_destroy(regex);

        return FLB_FALSE;
    }


    result = flb_regex_parse(regex,
                             &match_list,
                             attribute_match_cb,
                             (void *) span);

    flb_regex_destroy(regex);

    if (result == -1) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static int context_contains_attribute(struct ctrace *traces_context,
                                             char *name)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int hex_encode(unsigned char *input_buffer,
                      size_t input_length,
                      cfl_sds_t *output_buffer)
{
    const char hex[] = "0123456789abcdef";
    cfl_sds_t  result;
    size_t     index;

    if (cfl_sds_alloc(*output_buffer) <= (input_length * 2)) {
        result = cfl_sds_increase(*output_buffer,
                                  (input_length * 2) -
                                  cfl_sds_alloc(*output_buffer));

        if (result == NULL) {
            return FLB_FALSE;
        }

        *output_buffer = result;
    }

    for (index = 0; index < input_length; index++) {
        (*output_buffer)[index * 2 + 0] = hex[(input_buffer[index] >> 4) & 0xF];
        (*output_buffer)[index * 2 + 1] = hex[(input_buffer[index] >> 0) & 0xF];
    }

    cfl_sds_set_len(*output_buffer, input_length * 2);

    (*output_buffer)[index * 2] = '\0';

    return FLB_TRUE;
}

static int hash_transformer(void *context, struct cfl_variant *value)
{
    unsigned char       digest_buffer[32];
    struct cfl_variant *converted_value;
    cfl_sds_t           encoded_hash;
    int                 result;

    if (value == NULL) {
        return FLB_FALSE;
    }

    result = cfl_variant_convert(value,
                                 &converted_value,
                                 CFL_VARIANT_STRING);

    if (result != FLB_TRUE) {
        return FLB_FALSE;
    }

    if (cfl_sds_len(converted_value->data.as_string) == 0) {
        cfl_variant_destroy(converted_value);

        return FLB_TRUE;
    }

    result = flb_hash_simple(FLB_HASH_SHA256,
                             (unsigned char *) converted_value->data.as_string,
                             cfl_sds_len(converted_value->data.as_string),
                             digest_buffer,
                             sizeof(digest_buffer));

    if (result != FLB_CRYPTO_SUCCESS) {
        cfl_variant_destroy(converted_value);

        return FLB_FALSE;
    }

    result = hex_encode(digest_buffer,
                        sizeof(digest_buffer),
                        &converted_value->data.as_string);

    if (result != FLB_TRUE) {
        cfl_variant_destroy(converted_value);

        return FLB_FALSE;
    }

    encoded_hash = cfl_sds_create(converted_value->data.as_string);

    if (encoded_hash == NULL) {
        cfl_variant_destroy(converted_value);

        return FLB_FALSE;
    }

    if (value->type == CFL_VARIANT_STRING ||
        value->type == CFL_VARIANT_BYTES) {
        cfl_sds_destroy(value->data.as_string);
    }
    else if (value->type == CFL_VARIANT_ARRAY) {
        cfl_array_destroy(value->data.as_array);
    }
    else if (value->type == CFL_VARIANT_KVLIST) {
        cfl_kvlist_destroy(value->data.as_kvlist);
    }

    value->type = CFL_VARIANT_STRING;
    value->data.as_string = encoded_hash;

    return FLB_TRUE;
}

static int traces_context_hash_attribute(struct ctrace *traces_context,
                                         char *name)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_transform_attribute(span, name, hash_transformer) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_remove_attribute(struct ctrace *traces_context,
                                             char *name)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_remove_attribute(span, name) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_update_attribute(struct ctrace *traces_context,
                                           char *name,
                                           char *value)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_update_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_insert_attribute(struct ctrace *traces_context,
                                           char *name,
                                           char *value)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (!span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_insert_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_upsert_attribute(struct ctrace *traces_context,
                                           char *name,
                                           char *value)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_update_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
        else {
            if (span_insert_attribute(span, name, value) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_convert_attribute(struct ctrace *traces_context,
                                            char *name,
                                            char *new_type)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_convert_attribute(span, name, new_type) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

static int traces_context_extract_attribute(struct ctrace *traces_context,
                                            char *name,
                                            char *pattern)
{
    struct cfl_list    *iterator;
    struct ctrace_span *span;

    cfl_list_foreach(iterator, &traces_context->span_list) {
        span = cfl_list_entry(iterator,
                              struct ctrace_span, _head_global);

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            if (span_extract_attributes(span, name, pattern) != FLB_TRUE) {
                return FLB_FALSE;
            }
        }
    }

    return FLB_TRUE;
}

int traces_delete_attributes(struct ctrace *traces_context, struct mk_list *attributes)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, attributes) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = context_contains_attribute(traces_context, entry->str);
        if (result == FLB_TRUE) {
            result = traces_context_remove_attribute(traces_context, entry->str);

            if (result == FLB_FALSE) {
                return FLB_PROCESSOR_FAILURE;
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

int traces_update_attributes(struct ctrace *traces_context, struct cfl_list *attributes)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, attributes) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = traces_context_update_attribute(traces_context,
                                                 pair->key,
                                                 pair->val);

        if (result == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

int traces_upsert_attributes(struct ctrace *traces_context, struct cfl_list *attributes)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, attributes) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = traces_context_upsert_attribute(traces_context,
                                                 pair->key,
                                                 pair->val);

        if (result == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

int traces_convert_attributes(struct ctrace *traces_context, struct cfl_list *attributes)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, attributes) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = traces_context_convert_attribute(traces_context,
                                                  pair->key,
                                                  pair->val);

        if (result == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

int traces_extract_attributes(struct ctrace *traces_context, struct cfl_list *attributes)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, attributes) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = traces_context_extract_attribute(traces_context,
                                                  pair->key,
                                                  pair->val);

        if (result == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

int traces_insert_attributes(struct ctrace *traces_context, struct cfl_list *attributes)
{
    struct cfl_list *iterator;
    int              result;
    struct cfl_kv   *pair;

    cfl_list_foreach(iterator, attributes) {
        pair = cfl_list_entry(iterator, struct cfl_kv, _head);

        result = traces_context_insert_attribute(traces_context,
                                                 pair->key,
                                                 pair->val);

        if (result == FLB_FALSE) {
            return FLB_PROCESSOR_FAILURE;
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

int traces_hash_attributes(struct ctrace *traces_context, struct mk_list *attributes)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, attributes) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = context_contains_attribute(traces_context,
                                                   entry->str);

        if (result == FLB_TRUE) {
            result = traces_context_hash_attribute(traces_context,
                                                   entry->str);

            if (result == FLB_FALSE) {
                return FLB_PROCESSOR_FAILURE;
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}
