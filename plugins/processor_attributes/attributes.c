/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <stdio.h>
#include <math.h>

#include <fluent-bit/flb_regex.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_processor_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_processor.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>

#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_histogram.h>
#include <cmetrics/cmt_summary.h>
#include <cmetrics/cmt_untyped.h>
#include <cmetrics/cmt_counter.h>
#include <cmetrics/cmt_gauge.h>
#include <cmetrics/cmt_map.h>

#include <cfl/cfl.h>

#include "variant_utils.h"

typedef int (*attribute_transformer)(void *, struct cfl_variant *value);

struct internal_processor_context {
    struct mk_list *update_list;
    struct mk_list *insert_list;
    struct mk_list *upsert_list;
    struct mk_list *convert_list;
    struct mk_list *extract_list;
    struct mk_list *delete_list;
    struct mk_list *hash_list;

    /* internal attributes ready to append */
    struct cfl_list update_attributes;
    struct cfl_list insert_attributes;
    struct cfl_list upsert_attributes;
    struct cfl_list convert_attributes;
    struct cfl_list extract_attributes;
    struct mk_list  delete_attributes;
    struct mk_list  hash_attributes;

    struct flb_processor_instance *instance;
    struct flb_config *config;
};

/*
 * LOCAL
 */
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

static int process_attribute_modification_list_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct mk_list *destination_list)
{
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    int                        result;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        result = flb_slist_add(destination_list, source_entry->val.str);

        if (result != 0) {
            flb_plg_error(plugin_instance,
                          "could not append attribute name %s\n",
                          source_entry->val.str);

            return -1;
        }
    }

    return 0;
}

static int process_attribute_modification_kvlist_setting(
                struct flb_processor_instance *plugin_instance,
                const char *setting_name,
                struct mk_list *source_list,
                struct cfl_list *destination_list)
{
    struct cfl_kv             *processed_pair;
    struct flb_config_map_val *source_entry;
    struct mk_list            *iterator;
    struct flb_slist_entry    *value;
    struct flb_slist_entry    *key;

    if (source_list == NULL ||
        mk_list_is_empty(source_list) == 0) {

        return 0;
    }

    flb_config_map_foreach(iterator, source_entry, source_list) {
        if (mk_list_size(source_entry->val.list) != 2) {
            flb_plg_error(plugin_instance,
                          "'%s' expects a key and a value, "
                          "e.g: '%s version 1.8.0'",
                          setting_name, setting_name);

            return -1;
        }

        key = mk_list_entry_first(source_entry->val.list,
                                  struct flb_slist_entry, _head);

        value = mk_list_entry_last(source_entry->val.list,
                                   struct flb_slist_entry, _head);

        processed_pair = cfl_kv_item_create(destination_list,
                                            key->str,
                                            value->str);

        if (processed_pair == NULL) {
            flb_plg_error(plugin_instance,
                          "could not append attribute %s=%s\n",
                          key->str,
                          value->str);

            return -1;
        }
    }

    return 0;
}

static void destroy_context(struct internal_processor_context *context)
{
    if (context != NULL) {
        cfl_kv_release(&context->update_attributes);
        cfl_kv_release(&context->insert_attributes);
        cfl_kv_release(&context->upsert_attributes);
        cfl_kv_release(&context->convert_attributes);
        cfl_kv_release(&context->extract_attributes);
        flb_slist_destroy(&context->delete_attributes);
        flb_slist_destroy(&context->hash_attributes);

        flb_free(context);
    }
}

static struct internal_processor_context *
        create_context(struct flb_processor_instance *processor_instance,
                       struct flb_config *config)
{
    struct internal_processor_context *context;
    int                                result;

    context = flb_calloc(1, sizeof(struct internal_processor_context));

    if (context != NULL) {
        context->instance = processor_instance;
        context->config = config;

        cfl_kv_init(&context->update_attributes);
        cfl_kv_init(&context->insert_attributes);
        cfl_kv_init(&context->upsert_attributes);
        cfl_kv_init(&context->convert_attributes);
        cfl_kv_init(&context->extract_attributes);
        flb_slist_create(&context->delete_attributes);
        flb_slist_create(&context->hash_attributes);

        result = flb_processor_instance_config_map_set(processor_instance, (void *) context);

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "update",
                        context->update_list,
                        &context->update_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "insert",
                        context->insert_list,
                        &context->insert_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "convert",
                        context->convert_list,
                        &context->convert_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "extract",
                        context->extract_list,
                        &context->extract_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_kvlist_setting(
                        processor_instance,
                        "upsert",
                        context->upsert_list,
                        &context->upsert_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_list_setting(
                        processor_instance,
                        "delete",
                        context->delete_list,
                        &context->delete_attributes);
        }

        if (result == 0) {
            result = process_attribute_modification_list_setting(
                        processor_instance,
                        "hash",
                        context->hash_list,
                        &context->hash_attributes);
        }

        if (result != 0) {
            destroy_context(context);

            context = NULL;
        }
    }
    else {
        flb_errno();
    }

    return context;
}

static int cb_init(struct flb_processor_instance *processor_instance,
                   void *source_plugin_instance,
                   int source_plugin_type,
                   struct flb_config *config)
{
    processor_instance->context = (void *) create_context(
                                            processor_instance, config);

    if (processor_instance->context == NULL) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}


static int cb_exit(struct flb_processor_instance *processor_instance)
{
    if (processor_instance != NULL &&
        processor_instance->context != NULL) {
        destroy_context(processor_instance->context);
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int cfl_kvlist_contains(struct cfl_kvlist *kvlist,
                               char *name)
{
    struct cfl_list   *iterator;
    struct cfl_kvpair *pair;

    cfl_list_foreach(iterator, &kvlist->list) {
        pair = cfl_list_entry(iterator,
                              struct cfl_kvpair, _head);

        if (strcasecmp(pair->key, name) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static void cfl_kvpair_destroy(struct cfl_kvpair *pair)
{
    if (pair != NULL) {
        if (!cfl_list_entry_is_orphan(&pair->_head)) {
            cfl_list_del(&pair->_head);
        }

        if (pair->key != NULL) {
            cfl_sds_destroy(pair->key);
        }

        if (pair->val != NULL) {
            cfl_variant_destroy(pair->val);
        }

        free(pair);
    }
}

static int cfl_kvlist_remove(struct cfl_kvlist *kvlist,
                             char *name)
{
    struct cfl_list   *iterator_backup;
    struct cfl_list   *iterator;
    struct cfl_kvpair *pair;

    cfl_list_foreach_safe(iterator, iterator_backup, &kvlist->list) {
        pair = cfl_list_entry(iterator,
                              struct cfl_kvpair, _head);

        if (strcasecmp(pair->key, name) == 0) {
            cfl_kvpair_destroy(pair);
        }
    }

    return FLB_TRUE;
}


/* local declarations */


static cfl_sds_t cfl_variant_convert_to_json(struct cfl_variant *value)
{
    cfl_sds_t      json_result;
    mpack_writer_t writer;
    char          *data;
    size_t         size;

    data = NULL;
    size = 0;

    mpack_writer_init_growable(&writer, &data, &size);

    pack_cfl_variant(&writer, value);

    mpack_writer_destroy(&writer);

    json_result = flb_msgpack_raw_to_json_sds(data, size);

    return json_result;
}



static int cfl_variant_convert(struct cfl_variant *input_value,
                               struct cfl_variant **output_value,
                               int output_type)
{
    char              *converstion_canary;
    struct cfl_variant temporary_value;
    int                errno_backup;

    errno_backup = errno;
    *output_value = cfl_variant_create();

    memset(&temporary_value, 0, sizeof(struct cfl_variant));

    temporary_value.type = output_type;

    if (input_value->type == CFL_VARIANT_STRING ||
        input_value->type == CFL_VARIANT_BYTES ||
        input_value->type == CFL_VARIANT_REFERENCE) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string =
                cfl_sds_create_len(
                    input_value->data.as_string,
                    cfl_sds_len(input_value->data.as_string));

            if (temporary_value.data.as_string == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            temporary_value.data.as_bool = CFL_FALSE;

            if (strcasecmp(input_value->data.as_string, "true") == 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
            else if (strcasecmp(input_value->data.as_string, "off") == 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
        }
        else if (output_type == CFL_VARIANT_INT) {
            errno = 0;
            temporary_value.data.as_int64 = strtoimax(input_value->data.as_string,
                                                      &converstion_canary,
                                                      10);

            if (errno == ERANGE || errno == EINVAL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                errno = errno_backup;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            errno = 0;
            converstion_canary = NULL;
            temporary_value.data.as_double = strtod(input_value->data.as_string,
                                                    &converstion_canary);

            if (errno == ERANGE) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                errno = errno_backup;

                return CFL_FALSE;
            }
            else if (temporary_value.data.as_double == 0 &&
                     converstion_canary == input_value->data.as_string) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                errno = errno_backup;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_ARRAY) {
            temporary_value.data.as_array = cfl_array_create(1);

            if (temporary_value.data.as_array == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            if (cfl_array_append_bytes(temporary_value.data.as_array,
                                       input_value->data.as_bytes,
                                       cfl_sds_len(input_value->data.as_bytes)) != 0) {
                cfl_array_destroy(temporary_value.data.as_array);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            temporary_value.data.as_array->entries[0]->type = output_type;
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_INT) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_sds_create_size(64);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }

            /* We need to fix the wesleys truncation PR to cfl */
            converstion_canary = (char *) cfl_sds_printf(
                                            &temporary_value.data.as_string,
                                            "%" PRIi64,
                                            input_value->data.as_int64);

            if (converstion_canary == NULL) {
                cfl_sds_destroy(temporary_value.data.as_string);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            temporary_value.data.as_bool = CFL_FALSE;

            if (input_value->data.as_int64 != 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
        }
        else if (output_type == CFL_VARIANT_INT) {
            temporary_value.data.as_int64 = input_value->data.as_int64;
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            temporary_value.data.as_double = (double) input_value->data.as_int64;

            /* This conversion could be lossy, we need to determine what we want to
             * do in that case
             */
            if ((int64_t) temporary_value.data.as_double != input_value->data.as_int64) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_ARRAY) {
            temporary_value.data.as_array = cfl_array_create(1);

            if (temporary_value.data.as_array == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            if (cfl_array_append_int64(temporary_value.data.as_array,
                                       input_value->data.as_int64) != 0) {
                cfl_array_destroy(temporary_value.data.as_array);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_DOUBLE) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_sds_create_size(64);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }

            /* We need to fix the wesleys truncation PR to cfl */
            converstion_canary = (char *) cfl_sds_printf(
                                            &temporary_value.data.as_string,
                                            "%.17g",
                                            input_value->data.as_double);

            if (converstion_canary == NULL) {
                cfl_sds_destroy(temporary_value.data.as_string);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else if (output_type == CFL_VARIANT_BOOL) {
            temporary_value.data.as_bool = CFL_FALSE;

            if (input_value->data.as_double != 0) {
                temporary_value.data.as_bool = CFL_TRUE;
            }
        }
        else if (output_type == CFL_VARIANT_INT) {
            temporary_value.data.as_int64 = (int64_t) round(input_value->data.as_double);
        }
        else if (output_type == CFL_VARIANT_DOUBLE) {
            temporary_value.data.as_double = input_value->data.as_int64;
        }
        else if (output_type == CFL_VARIANT_ARRAY) {
            temporary_value.data.as_array = cfl_array_create(1);

            if (temporary_value.data.as_array == NULL) {
                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }

            if (cfl_array_append_double(temporary_value.data.as_array,
                                        input_value->data.as_double) != 0) {
                cfl_array_destroy(temporary_value.data.as_array);

                cfl_variant_destroy(*output_value);
                *output_value = NULL;

                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_KVLIST) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_variant_convert_to_json(input_value);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }
    else if (input_value->type == CFL_VARIANT_ARRAY) {
        if (output_type == CFL_VARIANT_STRING ||
            output_type == CFL_VARIANT_BYTES) {
            temporary_value.data.as_string = cfl_variant_convert_to_json(input_value);

            if (temporary_value.data.as_string == NULL) {
                return CFL_FALSE;
            }
        }
        else {
            return CFL_FALSE;
        }
    }

    memcpy(*output_value, &temporary_value, sizeof(struct cfl_variant));

    return FLB_TRUE;
}

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

        if (span_contains_attribute(span, name) == FLB_TRUE) {
            span_remove_attribute(span, name);
        }

        ctr_span_set_attribute_string(span, name, temporary_value);

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

static int traces_context_contains_attribute(struct ctrace *traces_context,
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

static int delete_attributes(struct ctrace *traces_context,
                             struct mk_list *attributes)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, attributes) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = traces_context_contains_attribute(traces_context,
                                                   entry->str);

        if (result == FLB_TRUE) {
            result = traces_context_remove_attribute(traces_context,
                                                     entry->str);

            if (result == FLB_FALSE) {
                return FLB_PROCESSOR_FAILURE;
            }
        }
    }

    return FLB_PROCESSOR_SUCCESS;
}

static int update_attributes(struct ctrace *traces_context,
                             struct cfl_list *attributes)
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

static int upsert_attributes(struct ctrace *traces_context,
                             struct cfl_list *attributes)
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

static int convert_attributes(struct ctrace *traces_context,
                              struct cfl_list *attributes)
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

static int extract_attributes(struct ctrace *traces_context,
                              struct cfl_list *attributes)
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

static int insert_attributes(struct ctrace *traces_context,
                             struct cfl_list *attributes)
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

static int hash_attributes(struct ctrace *traces_context,
                           struct mk_list *attributes)
{
    struct mk_list         *iterator;
    int                     result;
    struct flb_slist_entry *entry;

    mk_list_foreach(iterator, attributes) {
        entry = mk_list_entry(iterator, struct flb_slist_entry, _head);

        result = traces_context_contains_attribute(traces_context,
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

static int cb_process_traces(struct flb_processor_instance *processor_instance,
                              struct ctrace *traces_context,
                              const char *tag,
                              int tag_len)
{
    struct internal_processor_context *processor_context;
    int                                result;

    processor_context =
        (struct internal_processor_context *) processor_instance->context;

    result = delete_attributes(traces_context,
                               &processor_context->delete_attributes);

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = update_attributes(traces_context,
                                   &processor_context->update_attributes);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = upsert_attributes(traces_context,
                                   &processor_context->upsert_attributes);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = insert_attributes(traces_context,
                                   &processor_context->insert_attributes);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = convert_attributes(traces_context,
                                    &processor_context->convert_attributes);
        result = FLB_PROCESSOR_SUCCESS;
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = extract_attributes(traces_context,
                                    &processor_context->extract_attributes);
    }

    if (result == FLB_PROCESSOR_SUCCESS) {
        result = hash_attributes(traces_context,
                                 &processor_context->hash_attributes);
    }

    if (result != FLB_PROCESSOR_SUCCESS) {
        return FLB_PROCESSOR_FAILURE;
    }

    return FLB_PROCESSOR_SUCCESS;
}

static struct flb_config_map config_map[] = {
    {
        FLB_CONFIG_MAP_SLIST_1, "update", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                update_list),
        "Updates an attribute. Usage : 'update name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "insert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                insert_list),
        "Inserts an attribute. Usage : 'insert name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "upsert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                upsert_list),
        "Inserts or updates an attribute. Usage : 'upsert name value'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "convert", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                convert_list),
        "Converts an attribute. Usage : 'convert name new_type'"
    },
    {
        FLB_CONFIG_MAP_SLIST_1, "extract", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                extract_list),
        "Extracts regular expression match groups as individual attributes. Usage : 'extract (?P<first_word>[^ ]*) (?P<second_word>[^ ]*)'"
    },
    {
        FLB_CONFIG_MAP_STR, "delete", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                delete_list),
        "Deletes an attribute. Usage : 'delete name'"
    },
    {
        FLB_CONFIG_MAP_STR, "hash", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct internal_processor_context,
                                                hash_list),
        "Replaces an attributes value with its SHA256 hash. Usage : 'hash name'"
    },

    /* EOF */
    {0}
};

struct flb_processor_plugin processor_attributes_plugin = {
    .name               = "attributes",
    .description        = "Modifies metrics attributes",
    .cb_init            = cb_init,
    .cb_process_logs    = NULL,
    .cb_process_metrics = NULL,
    .cb_process_traces  = cb_process_traces,
    .cb_exit            = cb_exit,
    .config_map         = config_map,
    .flags              = 0
};
