/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  CProfiles
 *  =========
 *  Copyright (C) 2024 The CProfiles Authors
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


#include <cprofiles/cprof_encode_text.h>

static int increment_indentation_level(
            struct cprof_text_encoding_context *context);
static int decrement_indentation_level(
            struct cprof_text_encoding_context *context);

static int encode_bytes(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                uint8_t *value,
                size_t length,
                int hex_encode);

static int encode_string(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                char *value);

static int encode_double(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                double value);

static int encode_uint64_t(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                uint64_t value);

static int encode_int64_t(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                int64_t value);

static int encode_bool(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                bool value);

static int encode_string_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                char **data_list,
                size_t data_length);

static int encode_uint64_t_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                uint64_t *data_list,
                size_t data_length);

static int encode_int64_t_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                int64_t *data_list,
                size_t data_length);

static int encode_cfl_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                struct cfl_array *value);

static int encode_cfl_kvlist(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                struct cfl_kvlist *data_list);

static int encode_cfl_variant(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                struct cfl_variant *value);



static int encode_aggregation_temporality(
                struct cprof_text_encoding_context *context,
                enum aggregation_temporality instance);

static int encode_cprof_value_type(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_value_type *instance);

static int encode_cprof_sample(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_sample *instance);

static int encode_cprof_mapping(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_mapping *instance);

static int encode_cprof_line(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_line *instance);

static int encode_cprof_location(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_location *instance);

static int encode_cprof_function(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_function *instance);

static int encode_cprof_attribute_unit(
                struct cprof_text_encoding_context *context,
                struct cprof_attribute_unit *instance);


static int encode_cprof_link(
                struct cprof_text_encoding_context *context,
                struct cprof_link *instance);


static int encode_cprof_profile(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *instance);


static int encode_cprof_resource_profiles(
                struct cprof_text_encoding_context *context,
                struct cprof_resource_profiles *instance);


static int encode_cprof_instrumentation_scope(
                struct cprof_text_encoding_context *context,
                struct cprof_instrumentation_scope *instance);


static int encode_cprof_resource(
            struct cprof_text_encoding_context *context,
            struct cprof_resource *instance);


static int encode_cprof_scope_profiles(
                struct cprof_text_encoding_context *context,
                struct cprof_scope_profiles *instance);


static int increment_indentation_level(
            struct cprof_text_encoding_context *context) {
    if (context->indentation_level >= 255) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    if (context->indentation_buffer[0] == '\0' &&
        context->indentation_buffer[255] == '\0') {
        memset(context->indentation_buffer,
                context->indentation_character,
                255);
    }

    context->indentation_buffer[context->indentation_level] = context->indentation_character;

    context->indentation_level += context->indentation_level_size;

    context->indentation_buffer[context->indentation_level] = '\0';

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int decrement_indentation_level(
            struct cprof_text_encoding_context *context) {
    if (context->indentation_level <= 0) {
        return CPROF_ENCODE_TEXT_SUCCESS;
    }

    context->indentation_buffer[context->indentation_level] = context->indentation_character;

    context->indentation_level -= context->indentation_level_size;

    context->indentation_buffer[context->indentation_level] = '\0';

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_bytes(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                uint8_t *value,
                size_t length,
                int hex_encode)
{
    char      *local_indentation;
    cfl_sds_t  result;
    size_t     index;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    if (!hex_encode) {
        result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s" "%.*s" "%s",
                                local_indentation,
                                prefix,
                                length,
                                value,
                                suffix);

        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }
    }
    else {
        result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s" ,
                                local_indentation,
                                prefix);

        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }

        for (index = 0 ; index < length ; index++) {
            result = cfl_sds_printf(&context->output_buffer,
                                    "%02X",
                                    value[index]);

            if (result == NULL) {
                return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
            }
        }

        result = cfl_sds_printf(&context->output_buffer,
                                "%s",
                                suffix);

        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }

    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_string(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                char *value)
{
    char      *local_indentation;
    cfl_sds_t  result;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    result = cfl_sds_printf(&context->output_buffer,
                            "%s" "%s" "%s" "%s",
                            local_indentation,
                            prefix,
                            value,
                            suffix);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

/* Section header with count for debugging (e.g. "Samples (3) :") */
static int encode_section_header_with_count(
                struct cprof_text_encoding_context *context,
                const char *label,
                size_t count)
{
    cfl_sds_t result;

    result = cfl_sds_printf(&context->output_buffer,
                            "%s%s (%zu) :\n",
                            context->indentation_buffer,
                            label,
                            count);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

/* Item subheader with index for debugging (e.g. "Sample #0 :") */
static int encode_item_header(
                struct cprof_text_encoding_context *context,
                const char *label,
                size_t index)
{
    cfl_sds_t result;

    result = cfl_sds_printf(&context->output_buffer,
                            "%s%s #%zu :\n",
                            context->indentation_buffer,
                            label,
                            index);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_double(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                double value)
{
    char      *local_indentation;
    cfl_sds_t  result;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    result = cfl_sds_printf(&context->output_buffer,
                            "%s" "%s" "%0.4f" "%s",
                            local_indentation,
                            prefix,
                            value,
                            suffix);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_uint64_t(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                uint64_t value)
{
    char      *local_indentation;
    cfl_sds_t  result;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    result = cfl_sds_printf(&context->output_buffer,
                            "%s" "%s" "%"PRIu64 "%s",
                            local_indentation,
                            prefix,
                            value,
                            suffix);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_int64_t(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                int64_t value)
{
    char      *local_indentation;
    cfl_sds_t result;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    result = cfl_sds_printf(&context->output_buffer,
                            "%s" "%s" "%"PRId64 "%s",
                            local_indentation,
                            prefix,
                            value,
                            suffix);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

/* Resolve string_table index; returns pointer to string or NULL if invalid. */
static const char *resolve_string_index(struct cprof_profile *profile, int64_t index)
{
    if (profile == NULL || profile->string_table == NULL) {
        return NULL;
    }
    if (index < 0 || (size_t)index >= profile->string_table_count) {
        return NULL;
    }
    if (profile->string_table[index] == NULL) {
        return "";
    }
    return profile->string_table[index];
}

static struct cprof_mapping *resolve_mapping_index(struct cprof_profile *profile, uint64_t index)
{
    struct cfl_list      *iterator;
    struct cprof_mapping *mapping;
    uint64_t              current_index;

    if (profile == NULL) {
        return NULL;
    }

    current_index = 0;

    cfl_list_foreach(iterator, &profile->mappings) {
        mapping = cfl_list_entry(iterator, struct cprof_mapping, _head);

        if (current_index == index) {
            return mapping;
        }

        current_index++;
    }

    return NULL;
}

static struct cprof_location *resolve_location_index(struct cprof_profile *profile, uint64_t index)
{
    struct cfl_list       *iterator;
    struct cprof_location *location;
    uint64_t               current_index;

    if (profile == NULL) {
        return NULL;
    }

    current_index = 0;

    cfl_list_foreach(iterator, &profile->locations) {
        location = cfl_list_entry(iterator, struct cprof_location, _head);

        if (current_index == index) {
            return location;
        }

        current_index++;
    }

    return NULL;
}

static struct cprof_function *resolve_function_index(struct cprof_profile *profile, uint64_t index)
{
    struct cfl_list       *iterator;
    struct cprof_function *function;
    uint64_t               current_index;

    if (profile == NULL) {
        return NULL;
    }

    current_index = 0;

    cfl_list_foreach(iterator, &profile->functions) {
        function = cfl_list_entry(iterator, struct cprof_function, _head);

        if (current_index == index) {
            return function;
        }

        current_index++;
    }

    return NULL;
}

static struct cfl_kvpair *resolve_attribute_index(struct cprof_profile *profile, uint64_t index)
{
    struct cfl_list   *iterator;
    struct cfl_kvpair *entry;
    uint64_t           current_index;

    if (profile == NULL || profile->attribute_table == NULL) {
        return NULL;
    }

    current_index = 0;

    cfl_list_foreach(iterator, &profile->attribute_table->list) {
        entry = cfl_list_entry(iterator, struct cfl_kvpair, _head);

        if (current_index == index) {
            return entry;
        }

        current_index++;
    }

    return NULL;
}

/* Append string to buffer with double-quotes escaped as \". */
static int append_escaped_string(cfl_sds_t *buf, const char *str)
{
    cfl_sds_t result;
    const char *p;

    if (str == NULL) {
        return CPROF_ENCODE_TEXT_SUCCESS;
    }
    for (p = str; *p != '\0'; p++) {
        if (*p == '"') {
            result = cfl_sds_cat(*buf, "\\\"", 2);
        }
        else {
            result = cfl_sds_printf(buf, "%c", *p);
        }
        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }
        if (*p == '"') {
            *buf = result;
        }
    }
    return CPROF_ENCODE_TEXT_SUCCESS;
}

/* Encode int64 (string_table index) with optional resolution for debugging. */
static int encode_int64_string_ref(
                struct cprof_text_encoding_context *context,
                int indent,
                const char *label,
                int64_t value,
                struct cprof_profile *profile)
{
    const char *resolved;
    char       *local_indentation;
    cfl_sds_t  result;
    int        append_result;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    resolved = resolve_string_index(profile, value);

    if (context->render_mode == CPROF_ENCODE_TEXT_RENDER_RESOLVED &&
        resolved != NULL) {
        result = cfl_sds_printf(&context->output_buffer,
                                "%s%s\"",
                                local_indentation,
                                label);

        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }

        context->output_buffer = result;

        append_result = append_escaped_string(&context->output_buffer, resolved);
        if (append_result != CPROF_ENCODE_TEXT_SUCCESS) {
            return append_result;
        }

        result = cfl_sds_cat(context->output_buffer, "\"\n", 2);
        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }

        context->output_buffer = result;

        return CPROF_ENCODE_TEXT_SUCCESS;
    }

    result = cfl_sds_printf(&context->output_buffer,
                            "%s%s%" PRId64,
                            local_indentation,
                            label,
                            value);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    if (resolved != NULL) {
        result = cfl_sds_cat(context->output_buffer,
                             " → \"",
                             strlen(" → \""));
        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }
        context->output_buffer = result;
        append_result = append_escaped_string(&context->output_buffer, resolved);
        if (append_result != CPROF_ENCODE_TEXT_SUCCESS) {
            return append_result;
        }
        result = cfl_sds_cat(context->output_buffer, "\"\n", 2);
        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }
        context->output_buffer = result;
    }
    else {
        result = cfl_sds_cat(context->output_buffer, "\n", 1);
        if (result == NULL) {
            return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
        }
        context->output_buffer = result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_bool(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                bool value)
{
    char      *local_indentation;
    char      *local_value;
    cfl_sds_t result;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    if (value) {
        local_value = (char *) "True";
    }
    else {
        local_value = (char *) "False";
    }

    result = cfl_sds_printf(&context->output_buffer,
                            "%s" "%s" "%s" "%s",
                            local_indentation,
                            prefix,
                            local_value,
                            suffix);

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_string_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                char **data_list,
                size_t data_length)
{
    char     *local_indentation;
    cfl_sds_t sds_result;
    int       result;
    size_t    index;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s",
                                local_indentation,
                                prefix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    for (index = 0 ; index < data_length ; index++) {
        if (index < data_length - 1) {
            result = encode_string(context,
                                   CFL_FALSE,
                                   "\"",
                                   "\", ",
                                   data_list[index]);
        }
        else {
            result = encode_string(context,
                                   CFL_FALSE,
                                   "\"",
                                   "\"",
                                   data_list[index]);
        }

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s",
                                suffix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_uint64_t_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                uint64_t *data_list,
                size_t data_length)
{
    char     *local_indentation;
    cfl_sds_t sds_result;
    int       result;
    size_t    index;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s",
                                local_indentation,
                                prefix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    for (index = 0 ; index < data_length ; index++) {
        if (index < data_length - 1) {
            result = encode_uint64_t(context,
                                     CFL_FALSE,
                                     "",
                                     ", ",
                                     data_list[index]);
        }
        else {
            result = encode_uint64_t(context,
                                     CFL_FALSE,
                                     "",
                                     "",
                                     data_list[index]);
        }

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s",
                                suffix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_attribute_index_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                struct cprof_profile *profile,
                uint64_t *data_list,
                size_t data_length)
{
    char               *local_indentation;
    cfl_sds_t           sds_result;
    int                 result;
    size_t              index;
    struct cfl_kvpair  *attribute;
    int                 placeholder_attribute;

    if (context->render_mode != CPROF_ENCODE_TEXT_RENDER_RESOLVED) {
        return encode_uint64_t_array(context, indent, prefix, separator, suffix,
                                     data_list, data_length);
    }

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s",
                                local_indentation,
                                prefix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    for (index = 0; index < data_length; index++) {
        attribute = resolve_attribute_index(profile, data_list[index]);
        placeholder_attribute = CFL_FALSE;

        if (attribute != NULL &&
            attribute->key != NULL &&
            attribute->key[0] == '\0' &&
            attribute->val != NULL &&
            attribute->val->type == CFL_VARIANT_STRING &&
            attribute->val->data.as_string != NULL &&
            cfl_sds_len(attribute->val->data.as_string) == 0) {
            placeholder_attribute = CFL_TRUE;
        }

        if (attribute == NULL || attribute->val == NULL || placeholder_attribute) {
            result = encode_uint64_t(context,
                                     CFL_FALSE,
                                     "<missing:",
                                     ">",
                                     data_list[index]);
        }
        else {
            result = encode_string(context,
                                   CFL_FALSE,
                                   "\"",
                                   "\": ",
                                   attribute->key);
            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }

            result = encode_cfl_variant(context,
                                        CFL_FALSE,
                                        "",
                                        "",
                                        attribute->val);
        }

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        if (index + 1 < data_length) {
            result = encode_string(context,
                                   CFL_FALSE,
                                   "",
                                   "",
                                   separator);
            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }
    }

    sds_result = cfl_sds_printf(&context->output_buffer, "%s", suffix);
    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_location_reference_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                struct cprof_profile *profile,
                uint64_t *data_list,
                size_t data_length)
{
    char                  *local_indentation;
    cfl_sds_t              sds_result;
    int                    result;
    size_t                 index;
    struct cprof_location *location;
    struct cprof_line     *line;
    struct cprof_function *function;
    const char            *resolved;

    if (context->render_mode != CPROF_ENCODE_TEXT_RENDER_RESOLVED) {
        return encode_uint64_t_array(context, indent, prefix, separator, suffix,
                                     data_list, data_length);
    }

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s",
                                local_indentation,
                                prefix);
    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    for (index = 0; index < data_length; index++) {
        location = resolve_location_index(profile, data_list[index]);

        if (location == NULL || cfl_list_is_empty(&location->lines)) {
            result = encode_uint64_t(context,
                                     CFL_FALSE,
                                     "",
                                     "",
                                     data_list[index]);
        }
        else {
            line = cfl_list_entry_first(&location->lines, struct cprof_line, _head);
            function = resolve_function_index(profile, line->function_index);

            if (function != NULL) {
                resolved = resolve_string_index(profile, function->name);
            }
            else {
                resolved = NULL;
            }

            if (resolved == NULL) {
                result = encode_uint64_t(context,
                                         CFL_FALSE,
                                         "",
                                         "",
                                         data_list[index]);
            }
            else {
                result = encode_string(context,
                                       CFL_FALSE,
                                       "\"",
                                       "\"",
                                       (char *) resolved);
            }
        }

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        if (index + 1 < data_length) {
            result = encode_string(context,
                                   CFL_FALSE,
                                   "",
                                   "",
                                   separator);
            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }
    }

    sds_result = cfl_sds_printf(&context->output_buffer, "%s", suffix);
    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_int64_t_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                int64_t *data_list,
                size_t data_length)
{
    char     *local_indentation;
    cfl_sds_t sds_result;
    int       result;
    size_t    index;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s",
                                local_indentation,
                                prefix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    for (index = 0 ; index < data_length ; index++) {
        if (index < data_length - 1) {
            result = encode_int64_t(context,
                                    CFL_FALSE,
                                    "",
                                    ", ",
                                    data_list[index]);
        }
        else {
            result = encode_int64_t(context,
                                    CFL_FALSE,
                                    "",
                                    "",
                                    data_list[index]);
        }

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s",
                                suffix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_cfl_array(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                struct cfl_array *value)
{
    char              *local_indentation;
    cfl_sds_t          sds_result;
    int                result;
    size_t             index;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s",
                                local_indentation,
                                prefix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    for (index = 0 ; index < value->entry_count ; index++) {
        if (index < value->entry_count - 1) {
            result = encode_cfl_variant(context,
                                        CFL_FALSE,
                                        "",
                                        ", ",
                                        value->entries[index]);
        }
        else {
            result = encode_cfl_variant(context,
                                        CFL_FALSE,
                                        "",
                                        "",
                                        value->entries[index]);
        }

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s",
                                suffix);

    if (sds_result != NULL) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_cfl_kvlist(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *separator,
                char *suffix,
                struct cfl_kvlist *data_list)
{
    char              *local_indentation;
    struct cfl_kvpair *last_entry;
    cfl_sds_t          sds_result;
    struct cfl_list   *iterator;
    char              *value_prefix;
    char              *value_suffix;
    int                result;
    struct cfl_kvpair *entry;

    if (indent) {
        local_indentation = (char *) context->indentation_buffer;
    }
    else {
        local_indentation = (char *) "";
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s" "%s",
                                local_indentation,
                                prefix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    last_entry = cfl_list_entry_last(&data_list->list,
                                     struct cfl_kvpair,
                                     _head);

    cfl_list_foreach(iterator,
                     &data_list->list) {
        entry = cfl_list_entry(iterator,
                               struct cfl_kvpair, _head);

        result = encode_string(context,
                               CFL_FALSE,
                               "\"",
                               "\": ",
                               entry->key);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        value_prefix = "";
        value_suffix = "";

        if (entry->val != NULL &&
            (entry->val->type == CFL_VARIANT_STRING ||
             entry->val->type == CFL_VARIANT_BYTES)) {
            value_prefix = "\"";
            value_suffix = "\"";
        }

        result = encode_cfl_variant(context,
                                    CFL_FALSE,
                                    value_prefix,
                                    value_suffix,
                                    entry->val);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        if (entry != last_entry) {
            result = encode_string(context,
                                   CFL_FALSE,
                                   "",
                                   "",
                                   separator);
            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }
    }

    sds_result = cfl_sds_printf(&context->output_buffer,
                                "%s",
                                suffix);

    if (sds_result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_cfl_variant(
                struct cprof_text_encoding_context *context,
                int indent,
                char *prefix,
                char *suffix,
                struct cfl_variant *value)
{
    int result;

    switch (value->type) {
        case CFL_VARIANT_BOOL:
            result = encode_bool(context,
                                 indent,
                                 prefix,
                                 suffix,
                                 value->data.as_bool);
            break;

        case CFL_VARIANT_INT:
            result = encode_int64_t(context,
                                    indent,
                                    prefix,
                                    suffix,
                                    value->data.as_int64);
            break;

        case CFL_VARIANT_UINT:
            result = encode_uint64_t(context,
                                     indent,
                                     prefix,
                                     suffix,
                                     value->data.as_uint64);
            break;

        case CFL_VARIANT_DOUBLE:
            result = encode_double(context,
                                   indent,
                                   prefix,
                                   suffix,
                                   value->data.as_double);
            break;

        case CFL_VARIANT_NULL:
            result = encode_string(context,
                                   indent,
                                   prefix,
                                   suffix,
                                   "NULL");
            break;

        case CFL_VARIANT_REFERENCE:
            result = encode_string(context,
                                   indent,
                                   prefix,
                                   suffix,
                                   "Reference");
            break;

        case CFL_VARIANT_STRING:
            result = encode_string(context,
                                   indent,
                                   prefix,
                                   suffix,
                                   value->data.as_string);
            break;

        case CFL_VARIANT_BYTES:
            result = encode_bytes(context,
                                   indent,
                                   prefix,
                                   suffix,
                                   (uint8_t *) value->data.as_bytes,
                                   cfl_sds_len(value->data.as_bytes),
                                   CFL_TRUE);
            break;

        case CFL_VARIANT_ARRAY:
            result = encode_cfl_array(context,
                                      indent,
                                      prefix,
                                      ", ",
                                      suffix,
                                      value->data.as_array);
            break;

        case CFL_VARIANT_KVLIST:
            result = encode_cfl_kvlist(context,
                                       indent,
                                       prefix,
                                       ", ",
                                       suffix,
                                       value->data.as_kvlist);
            break;

        default:
            result = CPROF_ENCODE_TEXT_INVALID_ARGUMENT_ERROR;
    }

    return result;
}









static int encode_aggregation_temporality(
                struct cprof_text_encoding_context *context,
                enum aggregation_temporality instance) {
    cfl_sds_t result;

    switch (instance) {
        case CPROF_AGGREGATION_TEMPORALITY_UNSPECIFIED:
            result = cfl_sds_printf(&context->output_buffer,
                                    "%s%s\n",
                                    context->indentation_buffer,
                                    "UNSPECIFIED");
            break;

        case CPROF_AGGREGATION_TEMPORALITY_DELTA:
            result = cfl_sds_printf(&context->output_buffer,
                                    "%s%s\n",
                                    context->indentation_buffer,
                                    "DELTA");
            break;

        case CPROF_AGGREGATION_TEMPORALITY_CUMULATIVE:
            result = cfl_sds_printf(&context->output_buffer,
                                    "%s%s\n",
                                    context->indentation_buffer,
                                    "CUMULATIVE");
            break;

        default:
            result = cfl_sds_printf(&context->output_buffer,
                                    "%s" "UNRECOGNIZED VALUE : %d\n",
                                    context->indentation_buffer,
                                    (int) instance);
    }

    if (result == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_cprof_value_type(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_value_type *instance)
{
    int result;

    result = encode_int64_string_ref(context,
                                    CFL_TRUE,
                                    "Type : ",
                                    instance->type,
                                    profile);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_string_ref(context,
                                    CFL_TRUE,
                                    "Unit : ",
                                    instance->unit,
                                    profile);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return encode_aggregation_temporality(
                context,
                instance->aggregation_temporality);
}



static int encode_cprof_sample(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_sample *instance) {
    int result;

    result = encode_location_reference_array(context,
                                             CFL_TRUE,
                                             "Location index : [ ",
                                             ", ",
                                             "]\n",
                                             profile,
                                             instance->location_index,
                                             instance->location_index_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Locations start index : ",
                            "\n",
                            instance->locations_start_index);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Locations length : ",
                             "\n",
                             instance->locations_length);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t_array(context,
                                  CFL_TRUE,
                                  "Values : [ ",
                                  ", ",
                                  "]\n",
                                  instance->values,
                                  instance->value_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_attribute_index_array(context,
                                          CFL_TRUE,
                                          "Attributes : [ ",
                                          ", ",
                                          "]\n",
                                          profile,
                                          instance->attributes,
                                          instance->attributes_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Link (link_table index) : ",
                             "\n",
                             instance->link);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t_array(context,
                                   CFL_TRUE,
                                   "Timestamps : [ ",
                                   ", ",
                                   "]\n",
                                   instance->timestamps_unix_nano,
                                   instance->timestamps_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}









static int encode_cprof_mapping(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_mapping *instance)
{
    int result;

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Id : ",
                             "\n",
                             instance->id);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Memory start : ",
                             "\n",
                             instance->memory_start);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Memory limit : ",
                             "\n",
                             instance->memory_limit);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "File offset : ",
                             "\n",
                             instance->file_offset);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }


    result = encode_int64_string_ref(context,
                                    CFL_TRUE,
                                    "Filename : ",
                                    instance->filename,
                                    profile);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_attribute_index_array(context,
                                          CFL_TRUE,
                                          "Attributes : [ ",
                                          ", ",
                                          "]\n",
                                          profile,
                                          instance->attributes,
                                          instance->attributes_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_bool(context,
                         CFL_TRUE,
                         "Has functions : ",
                         "\n",
                         instance->has_functions);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_bool(context,
                         CFL_TRUE,
                         "Has filenames : ",
                         "\n",
                         instance->has_filenames);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_bool(context,
                         CFL_TRUE,
                         "Has line numbers : ",
                         "\n",
                         instance->has_line_numbers);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_bool(context,
                         CFL_TRUE,
                         "Has inline frames : ",
                         "\n",
                         instance->has_inline_frames);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}





static int encode_cprof_line(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_line *instance)
{
    struct cprof_function *function;
    const char            *resolved;
    int result;

    if (context->render_mode == CPROF_ENCODE_TEXT_RENDER_RESOLVED) {
        function = resolve_function_index(profile, instance->function_index);

        if (function != NULL) {
            resolved = resolve_string_index(profile, function->name);
        }
        else {
            resolved = NULL;
        }

        if (resolved != NULL) {
            result = encode_string(context,
                                   CFL_TRUE,
                                   "Function : ",
                                   "\n",
                                   (char *) resolved);
        }
        else {
            result = encode_uint64_t(context,
                                     CFL_TRUE,
                                     "Function index : ",
                                     "\n",
                                     instance->function_index);
        }
    }
    else {
        result = encode_uint64_t(context,
                                 CFL_TRUE,
                                 "Function index : ",
                                 "\n",
                                 instance->function_index);
    }

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Line : ",
                            "\n",
                            instance->line);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Column : ",
                            "\n",
                            instance->column);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}



static int encode_cprof_location(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_location *instance)
{
    struct cfl_list   *iterator;
    struct cprof_mapping *mapping;
    const char           *resolved;
    int                result;
    struct cprof_line *line;

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Id : ",
                             "\n",
                             instance->id);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    if (context->render_mode == CPROF_ENCODE_TEXT_RENDER_RESOLVED) {
        mapping = resolve_mapping_index(profile, instance->mapping_index);

        if (mapping != NULL) {
            resolved = resolve_string_index(profile, mapping->filename);
        }
        else {
            resolved = NULL;
        }

        if (resolved != NULL) {
            result = encode_string(context,
                                   CFL_TRUE,
                                   "Mapping : ",
                                   "\n",
                                   (char *) resolved);
        }
        else {
            result = encode_uint64_t(context,
                                     CFL_TRUE,
                                     "Mapping index : ",
                                     "\n",
                                     instance->mapping_index);
        }
    }
    else {
        result = encode_uint64_t(context,
                                 CFL_TRUE,
                                 "Mapping index : ",
                                 "\n",
                                 instance->mapping_index);
    }

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Address : ",
                             "\n",
                             instance->address);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    if (!cfl_list_is_empty(&instance->lines)) {
        result = encode_string(context,
                            CFL_TRUE,
                            "",
                            "\n",
                            "Lines :");

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        cfl_list_foreach(iterator,
                        &instance->lines) {
            line = cfl_list_entry(iterator,
                                struct cprof_line, _head);

            result = encode_cprof_line(context, profile, line);

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    result = encode_attribute_index_array(context,
                                          CFL_TRUE,
                                          "Attributes : [ ",
                                          ", ",
                                          "]\n",
                                          profile,
                                          instance->attributes,
                                          instance->attributes_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}




static int encode_cprof_function(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *profile,
                struct cprof_function *instance)
{
    int result;

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Id : ",
                             "\n",
                             instance->id);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_string_ref(context,
                                    CFL_TRUE,
                                    "Name : ",
                                    instance->name,
                                    profile);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_string_ref(context,
                                    CFL_TRUE,
                                    "System name : ",
                                    instance->system_name,
                                    profile);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_string_ref(context,
                                    CFL_TRUE,
                                    "Filename : ",
                                    instance->filename,
                                    profile);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Start line : ",
                            "\n",
                            instance->start_line);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}




static int encode_cprof_attribute_unit(
                struct cprof_text_encoding_context *context,
                struct cprof_attribute_unit *instance) {
    int result;

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Attribute key : ",
                            "\n",
                            instance->attribute_key);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Unit : ",
                            "\n",
                            instance->unit);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_cprof_link(
                struct cprof_text_encoding_context *context,
                struct cprof_link *instance)
{
    int result;

    result = encode_bytes(context,
                          CFL_TRUE,
                          "Trace id : ",
                          "\n",
                          instance->trace_id,
                          sizeof(instance->trace_id),
                          CFL_TRUE);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_bytes(context,
                          CFL_TRUE,
                          "Span id : ",
                          "\n",
                          instance->span_id,
                          sizeof(instance->span_id),
                          CFL_TRUE);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}


static int encode_cprof_profile(
                struct cprof_text_encoding_context *context,
                struct cprof_profile *instance) {
    struct cprof_attribute_unit *attribute_unit;
    struct cprof_value_type     *sample_type;
    struct cfl_list             *iterator;
    struct cprof_location       *location;
    struct cprof_function       *function;
    struct cprof_mapping        *mapping;
    struct cprof_sample         *sample;
    int                          result;
    struct cprof_link           *link;

    result = encode_bytes(context,
                          CFL_TRUE,
                          "Profile id : ",
                          "\n",
                          instance->profile_id,
                          sizeof(instance->profile_id),
                          CFL_TRUE);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Start time unix nano: ",
                            "\n",
                            instance->start_time_unix_nano);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "End time unix nano: ",
                            "\n",
                            instance->end_time_unix_nano);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_cfl_kvlist(context,
                               CFL_TRUE,
                               "Attributes: {",
                               ", ",
                               " }\n",
                               instance->attributes);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Dropped attributes: ",
                             "\n",
                             (uint64_t) instance->dropped_attributes_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    if (!cfl_list_is_empty(&instance->sample_type)) {
        result = encode_section_header_with_count(context,
                                                 "Sample types",
                                                 cfl_list_size(&instance->sample_type));

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        cfl_list_foreach(iterator,
                        &instance->sample_type) {
            sample_type = cfl_list_entry(
                            iterator,
                            struct cprof_value_type, _head);

            result = encode_cprof_value_type(context, instance, sample_type);

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    if (!cfl_list_is_empty(&instance->samples)) {
        result = encode_section_header_with_count(context,
                                                 "Samples",
                                                 cfl_list_size(&instance->samples));

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        {
            size_t sample_index = 0;
            cfl_list_foreach(iterator,
                            &instance->samples) {
                sample = cfl_list_entry(
                            iterator,
                            struct cprof_sample, _head);

                result = encode_item_header(context, "Sample", sample_index);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = increment_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = encode_cprof_sample(context, instance, sample);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = decrement_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                sample_index++;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    if (!cfl_list_is_empty(&instance->mappings)) {
        result = encode_section_header_with_count(context,
                                                 "Mappings",
                                                 cfl_list_size(&instance->mappings));

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        {
            size_t mapping_index = 0;
            cfl_list_foreach(iterator,
                            &instance->mappings) {
                mapping = cfl_list_entry(
                            iterator,
                            struct cprof_mapping, _head);

                result = encode_item_header(context, "Mapping", mapping_index);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = increment_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = encode_cprof_mapping(context, instance, mapping);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = decrement_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                mapping_index++;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    if (!cfl_list_is_empty(&instance->locations)) {
        result = encode_section_header_with_count(context,
                                                 "Locations",
                                                 cfl_list_size(&instance->locations));

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        {
            size_t location_index = 0;
            cfl_list_foreach(iterator,
                            &instance->locations) {
                location = cfl_list_entry(
                            iterator,
                            struct cprof_location, _head);

                result = encode_item_header(context, "Location", location_index);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = increment_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = encode_cprof_location(context, instance, location);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = decrement_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                location_index++;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    if (context->render_mode == CPROF_ENCODE_TEXT_RENDER_DICTIONARIES_AND_INDEXES) {
        result = encode_int64_t_array(context,
                                      CFL_TRUE,
                                      "Location indices : [ ",
                                      ", ",
                                      "]\n",
                                      instance->location_indices,
                                      instance->location_indices_count);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    if (!cfl_list_is_empty(&instance->functions)) {
        result = encode_section_header_with_count(context,
                                                 "Functions",
                                                 cfl_list_size(&instance->functions));

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        {
            size_t function_index = 0;
            cfl_list_foreach(iterator,
                            &instance->functions) {
                function = cfl_list_entry(
                            iterator,
                            struct cprof_function, _head);

                result = encode_item_header(context, "Function", function_index);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = increment_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = encode_cprof_function(context, instance, function);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = decrement_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                function_index++;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    if (context->render_mode == CPROF_ENCODE_TEXT_RENDER_DICTIONARIES_AND_INDEXES) {
        result = encode_cfl_kvlist(context,
                                   CFL_TRUE,
                                   "Attribute table : {",
                                   ", ",
                                   " }\n",
                                   instance->attribute_table);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        if (!cfl_list_is_empty(&instance->attribute_units)) {
            result = encode_section_header_with_count(context,
                                                     "Attribute units",
                                                     cfl_list_size(&instance->attribute_units));

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }

            result = increment_indentation_level(context);

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }

            cfl_list_foreach(iterator,
                             &instance->attribute_units) {
                attribute_unit = cfl_list_entry(
                                    iterator,
                                    struct cprof_attribute_unit, _head);

                result = encode_cprof_attribute_unit(context, attribute_unit);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }
            }

            result = decrement_indentation_level(context);

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }
    }

    if (!cfl_list_is_empty(&instance->link_table)) {
        result = encode_section_header_with_count(context,
                                                 "Links",
                                                 cfl_list_size(&instance->link_table));

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        {
            size_t link_index = 0;
            cfl_list_foreach(iterator,
                             &instance->link_table) {
                link = cfl_list_entry(
                        iterator,
                        struct cprof_link, _head);

                result = encode_item_header(context, "Link", link_index);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = increment_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = encode_cprof_link(context, link);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                result = decrement_indentation_level(context);

                if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                    return result;
                }

                link_index++;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    if (context->render_mode == CPROF_ENCODE_TEXT_RENDER_DICTIONARIES_AND_INDEXES) {
        result = encode_section_header_with_count(context,
                                                 "String table",
                                                 instance->string_table_count);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = encode_string_array(
                    context,
                    CFL_TRUE,
                    "[ ",
                    ", ",
                    " ]\n",
                    (char **) instance->string_table,
                    instance->string_table_count);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Drop frames : ",
                            "\n",
                            instance->drop_frames);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Keep frames : ",
                            "\n",
                            instance->keep_frames);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Time nanos : ",
                            "\n",
                            instance->time_nanos);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Duration nanos : ",
                            "\n",
                            instance->duration_nanos);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_string(context,
                            CFL_TRUE,
                            "",
                            "\n",
                            "Period type :");

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = increment_indentation_level(context);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_cprof_value_type(context, instance, &instance->period_type);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = decrement_indentation_level(context);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Period : ",
                            "\n",
                            instance->period);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t_array(context,
                                  CFL_TRUE,
                                  "Comments : [ ",
                                  ", ",
                                  "]\n",
                                  instance->comments,
                                  instance->comments_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_int64_t(context,
                            CFL_TRUE,
                            "Default sample type : ",
                            "\n",
                            instance->default_sample_type);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}

static int encode_cprof_resource_profiles(
                struct cprof_text_encoding_context *context,
                struct cprof_resource_profiles *instance) {
    int result;
    struct cfl_list             *iterator;
    struct cprof_scope_profiles *scope_profile;

    result = encode_string(context,
                            CFL_TRUE,
                            "",
                            "\n",
                            "Resource :");

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = increment_indentation_level(context);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_cprof_resource(context, instance->resource);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = decrement_indentation_level(context);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    if (!cfl_list_is_empty(&instance->scope_profiles)) {
        result = encode_string(context,
                               CFL_TRUE,
                               "",
                               "\n",
                               "Scope profiles :");

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        cfl_list_foreach(iterator,
                         &instance->scope_profiles) {
            scope_profile = cfl_list_entry(
                                iterator,
                                struct cprof_scope_profiles, _head);

            result = encode_cprof_scope_profiles(context, scope_profile);

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    result = encode_string(context,
                            CFL_TRUE,
                            "Schema URL :",
                            "\n",
                            instance->schema_url);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }


    return CPROF_ENCODE_TEXT_SUCCESS;
}




static int encode_cprof_instrumentation_scope(
                struct cprof_text_encoding_context *context,
                struct cprof_instrumentation_scope *instance) {
    int result;

    result = encode_string(context,
                            CFL_TRUE,
                            "Name : ",
                            "\n",
                            instance->name);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }


    result = encode_string(context,
                            CFL_TRUE,
                            "Version : ",
                            "\n",
                            instance->version);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_cfl_kvlist(context,
                               CFL_TRUE,
                               "Attributes: {",
                               ", ",
                               " }\n",
                               instance->attributes);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Dropped attribute count : ",
                             "\n",
                             (uint64_t) instance->dropped_attributes_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}



static int encode_cprof_resource(
            struct cprof_text_encoding_context *context,
            struct cprof_resource *instance) {
    int result;

    result = encode_cfl_kvlist(context,
                               CFL_TRUE,
                               "Attributes: {",
                               ", ",
                               " }\n",
                               instance->attributes);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_uint64_t(context,
                             CFL_TRUE,
                             "Dropped attribute count : ",
                             "\n",
                             (uint64_t) instance->dropped_attributes_count);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    return CPROF_ENCODE_TEXT_SUCCESS;
}





static int encode_cprof_scope_profiles(
                struct cprof_text_encoding_context *context,
                struct cprof_scope_profiles *instance) {
    int                   result;
    struct cfl_list      *iterator;
    struct cprof_profile *profile;

    result = encode_string(context,
                            CFL_TRUE,
                            "",
                            "\n",
                            "Instrumentation scope :");

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = increment_indentation_level(context);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = encode_cprof_instrumentation_scope(context, instance->scope);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    result = decrement_indentation_level(context);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }

    if (!cfl_list_is_empty(&instance->profiles)) {
        result = encode_string(context,
                               CFL_TRUE,
                               "",
                               "\n",
                               "Profiles :");

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        result = increment_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }

        cfl_list_foreach(iterator,
                         &instance->profiles) {
            profile = cfl_list_entry(
                        iterator,
                        struct cprof_profile, _head);

            result = encode_cprof_profile(context, profile);

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                return result;
            }
        }

        result = decrement_indentation_level(context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            return result;
        }
    }

    result = encode_string(context,
                            CFL_TRUE,
                            "Schema URL :",
                            "\n",
                            instance->schema_url);

    if (result != CPROF_ENCODE_TEXT_SUCCESS) {
        return result;
    }


    return CPROF_ENCODE_TEXT_SUCCESS;
}




















void print_profile(struct cprof_profile *profile)
{
    int i;
    int sample_index = 0;
    uint64_t location_idx;
    char *tmp;
    struct cfl_list *head;
    struct cfl_list *type_head;
    struct cprof_sample *sample;
    struct cprof_value_type *sample_type;

    printf("\n");
    printf("--- profile debug\n");
    printf("Profile Duration: %" PRId64 " nanoseconds\n\n", profile->duration_nanos);
    printf("Samples:\n");

    cfl_list_foreach(head, &profile->samples) {
        sample = cfl_list_entry(head, struct cprof_sample, _head);

        printf("  Sample #%d:\n", ++sample_index);

        printf("    Locations:\n");
        for (i = 0; i < sample->location_index_count; ++i) {
            location_idx = sample->location_index[i];
            tmp = profile->string_table[location_idx];
            if (tmp[0] == '\0') {
                printf("      [Empty String: No Function Name]\n");
            }
            else {
                printf("      Function: %s\n", tmp);
            }
        }

        printf("    Values:\n");
        size_t value_index = 0;
        cfl_list_foreach(type_head, &profile->sample_type) {
            sample_type = cfl_list_entry(type_head, struct cprof_value_type, _head);
            if (value_index < sample->value_count) {
                printf("      %s: %" PRId64 " %s\n",
                       profile->string_table[sample_type->type],
                       sample->values[value_index],
                       profile->string_table[sample_type->unit]);
            }
            value_index++;
        }

        if (sample->timestamps_count > 0) {
            printf("    Timestamps:\n");
            for (i = 0; i < sample->timestamps_count; ++i) {
                printf("      Timestamp %d: %" PRIu64 " ns\n", i, sample->timestamps_unix_nano[i]);
            }
        }
        else {
            printf("    [No Timestamps]\n");
        }

        printf("\n");  // Add space between samples for readability
    }
    printf("String Table:\n");
    for (i = 0; i < profile->string_table_count; i++) {
        printf("  %d: '%s'\n", i, profile->string_table[i]);
    }
    printf("\n");
}




int cprof_encode_text_create(cfl_sds_t *result_buffer,
                             struct cprof *profile,
                             int render_mode)
{
    int                                 result;
    struct cprof_text_encoding_context  context;
    struct cfl_list                    *iterator;
    struct cprof_resource_profiles     *resource_profiles;

    memset(&context, 0, sizeof(context));

    if (render_mode != CPROF_ENCODE_TEXT_RENDER_DICTIONARIES_AND_INDEXES &&
        render_mode != CPROF_ENCODE_TEXT_RENDER_RESOLVED) {
        return CPROF_ENCODE_TEXT_INVALID_ARGUMENT_ERROR;
    }

    context.output_buffer = cfl_sds_create_size(128);

    if (context.output_buffer == NULL) {
        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    context.indentation_buffer = cfl_sds_create_size(256);

    if (context.indentation_buffer == NULL) {
        cfl_sds_destroy(context.output_buffer);

        return CPROF_ENCODE_TEXT_ALLOCATION_ERROR;
    }

    memset(context.indentation_buffer,
           0,
           cfl_sds_alloc(context.indentation_buffer));

    context.indentation_level_size = 4;
    context.indentation_character = ' ';
    context.render_mode = render_mode;


    if (!cfl_list_is_empty(&profile->profiles)) {
        result = encode_string(&context,
                               CFL_TRUE,
                               "",
                               "\n",
                               "Profiles :");

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            cfl_sds_destroy(context.indentation_buffer);
            cfl_sds_destroy(context.output_buffer);

            return result;
        }

        result = increment_indentation_level(&context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            cfl_sds_destroy(context.indentation_buffer);
            cfl_sds_destroy(context.output_buffer);

            return result;
        }

        cfl_list_foreach(iterator,
                         &profile->profiles) {
            resource_profiles = cfl_list_entry(
                                iterator,
                                struct cprof_resource_profiles, _head);

            result = encode_cprof_resource_profiles(&context, resource_profiles);

            if (result != CPROF_ENCODE_TEXT_SUCCESS) {
                cfl_sds_destroy(context.indentation_buffer);
                cfl_sds_destroy(context.output_buffer);

                return result;
            }
        }

        result = decrement_indentation_level(&context);

        if (result != CPROF_ENCODE_TEXT_SUCCESS) {
            cfl_sds_destroy(context.indentation_buffer);
            cfl_sds_destroy(context.output_buffer);

            return result;
        }
    }

    cfl_sds_destroy(context.indentation_buffer);

    *result_buffer = context.output_buffer;

    return CPROF_ENCODE_TEXT_SUCCESS;
}

void cprof_encode_text_destroy(cfl_sds_t instance)
{
    if (instance != NULL) {
        cfl_sds_destroy(instance);
    }
}
