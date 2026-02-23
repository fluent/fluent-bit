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


#include <cprofiles/cprof_decode_opentelemetry.h>
#include <cfl/cfl_sds.h>

#include "cprof_opentelemetry_variant_helpers.c"

static inline size_t minimum_size(size_t first_size, size_t second_size)
{
    if (first_size < second_size) {
        return first_size;
    }

    return second_size;
}

static struct cprof_resource *
            decode_resource(
                Opentelemetry__Proto__Resource__V1__Resource *input_resource)
{
    struct cprof_resource *output_resource;
    struct cfl_kvlist     *attributes;
    int                    result;

    if (input_resource == NULL) {
        output_resource = cprof_resource_create(NULL);
        if (output_resource != NULL) {
            output_resource->dropped_attributes_count = 0;
        }
        return output_resource;
    }

    attributes = cfl_kvlist_create();

    if (attributes == NULL) {
        return NULL;
    }

    result = convert_kvarray_to_kvlist(attributes,
                                       input_resource->attributes,
                                       input_resource->n_attributes);

    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        cfl_kvlist_destroy(attributes);

        attributes = NULL;
    }

    output_resource = cprof_resource_create(attributes);

    if (output_resource == NULL) {
        if (attributes != NULL) {
            cfl_kvlist_destroy(attributes);
        }

        return NULL;
    }

    output_resource->dropped_attributes_count = input_resource->dropped_attributes_count;

    return output_resource;
}


static struct cprof_instrumentation_scope *decode_instrumentation_scope(
    Opentelemetry__Proto__Common__V1__InstrumentationScope *input_instrumentation_scope)
{
    struct cprof_instrumentation_scope *instrumentation_scope;
    int                                 result;

    instrumentation_scope = cprof_instrumentation_scope_create(
        input_instrumentation_scope->name,
        input_instrumentation_scope->version,
        NULL,
        input_instrumentation_scope->dropped_attributes_count);

    if (instrumentation_scope == NULL) {
        return NULL;
    }

    result = convert_kvarray_to_kvlist(instrumentation_scope->attributes,
                                       input_instrumentation_scope->attributes,
                                       input_instrumentation_scope->n_attributes);

    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        cprof_instrumentation_scope_destroy(instrumentation_scope);

        return NULL;
    }

    return instrumentation_scope;
}


static int decode_profile_sample_entry(struct cprof_sample *sample,
    Opentelemetry__Proto__Profiles__V1development__Sample *input_sample,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dictionary)
{
    int32_t location_index;
    int    result;
    size_t index;
    Opentelemetry__Proto__Profiles__V1development__Stack *stack;

    /* Resolve stack_index to location indices from dictionary.stack_table */
    if (dictionary != NULL && dictionary->stack_table != NULL &&
        input_sample->stack_index >= 0 &&
        (size_t)input_sample->stack_index < dictionary->n_stack_table) {
        stack = dictionary->stack_table[input_sample->stack_index];
        if (stack != NULL && stack->location_indices != NULL) {
            for (index = 0; index < stack->n_location_indices; index++) {
                location_index = stack->location_indices[index];

                if (location_index < 0 ||
                    (dictionary->location_table != NULL &&
                     (size_t) location_index >= dictionary->n_location_table)) {
                    return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
                }

                result = cprof_sample_add_location_index(sample,
                    (uint64_t) location_index);
                if (result != 0) {
                    return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
                }
            }
        }
    }

    for (index = 0; index < input_sample->n_values; index++) {
        result = cprof_sample_add_value(sample, input_sample->values[index]);
        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0; index < input_sample->n_attribute_indices; index++) {
        result = cprof_sample_add_attribute(sample,
            (uint64_t)input_sample->attribute_indices[index]);
        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0; index < input_sample->n_timestamps_unix_nano; index++) {
        result = cprof_sample_add_timestamp(sample,
            input_sample->timestamps_unix_nano[index]);
        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    sample->link = (uint64_t)(input_sample->link_index >= 0 ? input_sample->link_index : 0);

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}




static int decode_mapping_entry(struct cprof_mapping *mapping,
    Opentelemetry__Proto__Profiles__V1development__Mapping *input_mapping)
{
    int    result;
    size_t index;

    mapping->id = 0;
    mapping->memory_start = input_mapping->memory_start;
    mapping->memory_limit = input_mapping->memory_limit;
    mapping->file_offset = input_mapping->file_offset;
    mapping->filename = (int64_t)input_mapping->filename_strindex;
    mapping->has_functions = 0;
    mapping->has_filenames = 0;
    mapping->has_line_numbers = 0;
    mapping->has_inline_frames = 0;

    for (index = 0; index < input_mapping->n_attribute_indices; index++) {
        result = cprof_mapping_add_attribute(mapping,
            (uint64_t)input_mapping->attribute_indices[index]);
        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_line_entry(struct cprof_line *line,
    Opentelemetry__Proto__Profiles__V1development__Line *input_line,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dictionary)
{
    if (input_line->function_index < 0 ||
        (dictionary != NULL &&
         dictionary->function_table != NULL &&
         (size_t) input_line->function_index >= dictionary->n_function_table)) {
        return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    line->function_index = (uint64_t)input_line->function_index;
    line->line = input_line->line;
    line->column = input_line->column;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_location_entry(struct cprof_location *location,
    Opentelemetry__Proto__Profiles__V1development__Location *input_location,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dictionary)
{
    int                result;
    size_t             index;
    struct cprof_line *line;

    if (input_location->mapping_index < 0 ||
        (dictionary != NULL &&
         dictionary->mapping_table != NULL &&
         (size_t) input_location->mapping_index >= dictionary->n_mapping_table)) {
        return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    location->id = 0;
    location->mapping_index = (uint64_t)input_location->mapping_index;
    location->address = input_location->address;
    location->is_folded = 0;

    for (index = 0; index < input_location->n_lines; index++) {
        line = cprof_line_create(location);
        if (line == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
        result = decode_line_entry(line, input_location->lines[index], dictionary);
        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0; index < input_location->n_attribute_indices; index++) {
        result = cprof_location_add_attribute(location,
            (uint64_t)input_location->attribute_indices[index]);
        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_function_entry(struct cprof_function *function,
    Opentelemetry__Proto__Profiles__V1development__Function *input_function)
{
    function->id = 0;
    function->name = (int64_t)input_function->name_strindex;
    function->system_name = (int64_t)input_function->system_name_strindex;
    function->filename = (int64_t)input_function->filename_strindex;
    function->start_line = input_function->start_line;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_keyvalueandunit_entry(struct cprof_attribute_unit *attribute_unit,
    Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit *input_kv)
{
    attribute_unit->attribute_key = (int64_t)input_kv->key_strindex;
    attribute_unit->unit = (int64_t)input_kv->unit_strindex;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_link_table_entry(struct cprof_link *link,
    Opentelemetry__Proto__Profiles__V1development__Link *input_link)
{
    size_t viable_length;

    if (input_link->trace_id.data != NULL &&
        input_link->trace_id.len > 0) {
        viable_length = minimum_size(sizeof(link->trace_id),
                                        input_link->trace_id.len);

        memcpy(link->trace_id,
                input_link->trace_id.data,
                viable_length);
    }

    if (input_link->span_id.data != NULL &&
        input_link->span_id.len > 0) {
        viable_length = minimum_size(sizeof(link->span_id),
                                        input_link->span_id.len);

        memcpy(link->span_id,
                input_link->span_id.data,
                viable_length);
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}


static int decode_profile_entry(struct cprof_profile *profile,
    Opentelemetry__Proto__Profiles__V1development__Profile *input_profile,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dictionary)
{
    Opentelemetry__Proto__Profiles__V1development__KeyValueAndUnit *indexed_attribute_entry;
    struct cprof_attribute_unit *attribute_unit;
    struct cprof_value_type     *sample_type;
    struct cprof_location       *location;
    struct cprof_function       *function;
    struct cprof_mapping        *mapping;
    struct cprof_sample         *sample;
    struct cprof_link           *link;
    struct cfl_variant          *indexed_attribute_value;
    int32_t                      indexed_attribute_key_index;
    int32_t                      indexed_attribute_table_index;
    char                        *indexed_attribute_key;
    int                          result;
    size_t                       index;

    /* Copy dictionary tables into profile when dictionary is present */
    if (dictionary != NULL) {
        /* String table */
        if (dictionary->string_table != NULL) {
            size_t table_size;

            table_size = dictionary->n_string_table;

            if (table_size == 0) {
                table_size = 1;
            }

            profile->string_table = calloc(table_size, sizeof(cfl_sds_t));
            if (profile->string_table == NULL) {
                return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }

            profile->string_table_size = table_size;
            profile->string_table_count = table_size;

            for (index = 0; index < table_size; index++) {
                const char *s;

                if (index < dictionary->n_string_table) {
                    s = dictionary->string_table[index];
                }
                else {
                    s = "";
                }

                profile->string_table[index] = cfl_sds_create(s != NULL ? s : "");
                if (profile->string_table[index] == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
            }
        }

        /* Mappings */
        if (dictionary->mapping_table != NULL) {
            for (index = 0; index < dictionary->n_mapping_table; index++) {
                mapping = cprof_mapping_create(profile);
                if (mapping == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
                result = decode_mapping_entry(mapping, dictionary->mapping_table[index]);
                if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                    return result;
                }
            }
        }

        /* Locations */
        if (dictionary->location_table != NULL) {
            for (index = 0; index < dictionary->n_location_table; index++) {
                location = cprof_location_create(profile);
                if (location == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
                result = decode_location_entry(location,
                                              dictionary->location_table[index],
                                              dictionary);
                if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                    return result;
                }
            }
        }

        /* Functions */
        if (dictionary->function_table != NULL) {
            for (index = 0; index < dictionary->n_function_table; index++) {
                function = cprof_function_create(profile);
                if (function == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
                result = decode_function_entry(function, dictionary->function_table[index]);
                if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                    return result;
                }
            }
        }

        /* Attribute table (KeyValueAndUnit) and attribute_units */
        if (dictionary->attribute_table != NULL && dictionary->n_attribute_table > 0) {
            result = convert_keyvalueandunit_array_to_kvlist(profile->attribute_table,
                dictionary->attribute_table,
                dictionary->n_attribute_table,
                dictionary->string_table,
                dictionary->n_string_table);
            if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                return result;
            }
            for (index = 0; index < dictionary->n_attribute_table; index++) {
                attribute_unit = cprof_attribute_unit_create(profile);
                if (attribute_unit == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
                result = decode_keyvalueandunit_entry(attribute_unit,
                    dictionary->attribute_table[index]);
                if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                    return result;
                }
            }
        }

        /* Link table */
        if (dictionary->link_table != NULL) {
            for (index = 0; index < dictionary->n_link_table; index++) {
                link = cprof_link_create(profile);
                if (link == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
                result = decode_link_table_entry(link, dictionary->link_table[index]);
                if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                    return result;
                }
            }
        }

        /* Profile attributes reference dictionary.attribute_table by index */
        if (input_profile->attribute_indices != NULL &&
            input_profile->n_attribute_indices > 0) {
            for (index = 0; index < input_profile->n_attribute_indices; index++) {
                indexed_attribute_table_index = input_profile->attribute_indices[index];

                if (indexed_attribute_table_index < 0 ||
                    (size_t) indexed_attribute_table_index >= dictionary->n_attribute_table) {
                    return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
                }

                indexed_attribute_entry = dictionary->attribute_table[indexed_attribute_table_index];

                if (indexed_attribute_entry == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
                }

                indexed_attribute_key = "";
                indexed_attribute_key_index = indexed_attribute_entry->key_strindex;

                if (dictionary->string_table != NULL &&
                    indexed_attribute_key_index >= 0 &&
                    (size_t) indexed_attribute_key_index < dictionary->n_string_table &&
                    dictionary->string_table[indexed_attribute_key_index] != NULL) {
                    indexed_attribute_key = dictionary->string_table[indexed_attribute_key_index];
                }

                indexed_attribute_value = clone_variant(indexed_attribute_entry->value);

                if (indexed_attribute_value == NULL) {
                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }

                if (cfl_kvlist_insert(profile->attributes,
                                      indexed_attribute_key,
                                      indexed_attribute_value) != 0) {
                    cfl_variant_destroy(indexed_attribute_value);

                    return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
                }
            }
        }
    }

    /* Profile sample_type (single ValueType in new proto) */
    if (input_profile->sample_type != NULL) {
        sample_type = cprof_sample_type_create(profile,
            (int64_t)input_profile->sample_type->type_strindex,
            (int64_t)input_profile->sample_type->unit_strindex,
            0);
        if (sample_type == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    /* Samples */
    if (input_profile->samples != NULL) {
        for (index = 0; index < input_profile->n_samples; index++) {
            sample = cprof_sample_create(profile);
            if (sample == NULL) {
                return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
            }
            result = decode_profile_sample_entry(sample,
                input_profile->samples[index], dictionary);
            if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                return result;
            }
        }
    }

    profile->time_nanos = (int64_t)input_profile->time_unix_nano;
    profile->duration_nanos = (int64_t)input_profile->duration_nano;
    profile->drop_frames = 0;
    profile->keep_frames = 0;
    profile->period = input_profile->period;

    if (input_profile->period_type != NULL) {
        profile->period_type.type = (int64_t)input_profile->period_type->type_strindex;
        profile->period_type.unit = (int64_t)input_profile->period_type->unit_strindex;
        profile->period_type.aggregation_temporality = 0;
    }

    profile->default_sample_type = 0;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_profile_into_scope(struct cprof_scope_profiles *scope_profiles,
    Opentelemetry__Proto__Profiles__V1development__Profile *input_profile,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dictionary)
{
    struct cprof_profile *profile;
    int                   result;

    profile = cprof_profile_create();
    if (profile == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    /* Profile-level fields (no ProfileContainer in new proto) */
    if (input_profile->profile_id.data != NULL && input_profile->profile_id.len >= 16) {
        memcpy(profile->profile_id, input_profile->profile_id.data, 16);
    }
    else {
        memset(profile->profile_id, 0, sizeof(profile->profile_id));
    }

    profile->start_time_unix_nano = (int64_t)input_profile->time_unix_nano;
    profile->end_time_unix_nano = (int64_t)input_profile->time_unix_nano +
        (int64_t)input_profile->duration_nano;

    profile->dropped_attributes_count = input_profile->dropped_attributes_count;

    if (input_profile->original_payload_format != NULL && input_profile->original_payload_format[0] != '\0') {
        profile->original_payload_format = cfl_sds_create(input_profile->original_payload_format);
        if (profile->original_payload_format == NULL) {
            cprof_profile_destroy(profile);
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    if (input_profile->original_payload.data != NULL && input_profile->original_payload.len > 0) {
        profile->original_payload = cfl_sds_create_len(
            (const char *)input_profile->original_payload.data,
            input_profile->original_payload.len);
        if (profile->original_payload == NULL) {
            cprof_profile_destroy(profile);
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    result = decode_profile_entry(profile, input_profile, dictionary);
    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        cprof_profile_destroy(profile);
        return result;
    }

    cfl_list_add(&profile->_head, &scope_profiles->profiles);
    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_scope_profiles_entry(struct cprof_resource_profiles *resource_profiles,
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *input_scope_profiles,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dictionary)
{
    struct cprof_scope_profiles *profiles;
    int                          result;
    size_t                       index;

    profiles = cprof_scope_profiles_create(
        resource_profiles,
        input_scope_profiles->schema_url != NULL ? input_scope_profiles->schema_url : "");

    if (profiles == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (input_scope_profiles->scope != NULL) {
        profiles->scope = decode_instrumentation_scope(input_scope_profiles->scope);
    }
    else {
        profiles->scope = cprof_instrumentation_scope_create(NULL, NULL, NULL, 0);
    }

    if (profiles->scope == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (input_scope_profiles->profiles != NULL && input_scope_profiles->n_profiles > 0) {
        for (index = 0; index < input_scope_profiles->n_profiles; index++) {
            result = decode_profile_into_scope(profiles,
                input_scope_profiles->profiles[index], dictionary);
            if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                return result;
            }
        }
    }

    /* cprof_scope_profiles_create already added profiles to resource_profiles */
    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_resource_profiles_entry(struct cprof *context,
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *resource_profile,
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary *dictionary)
{
    struct cprof_resource_profiles *profile;
    int                             result;
    size_t                          index;

    profile = cprof_resource_profiles_create(
        resource_profile->schema_url != NULL ? resource_profile->schema_url : "");

    if (profile == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    profile->resource = decode_resource(resource_profile->resource);

    if (profile->resource == NULL) {
        cprof_resource_profiles_destroy(profile);

        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    if (resource_profile->scope_profiles != NULL && resource_profile->n_scope_profiles > 0) {
        for (index = 0;
             result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
             index < resource_profile->n_scope_profiles;
             index++) {
            result = decode_scope_profiles_entry(profile,
                resource_profile->scope_profiles[index], dictionary);
        }
    }

    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        cprof_resource_profiles_destroy(profile);
        return result;
    }

    result = cprof_resource_profiles_add(context, profile);

    if (result != 0) {
        cprof_resource_profiles_destroy(profile);

        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_service_request(struct cprof *context,
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *service_request)
{
    int                                                                                     result;
    size_t                                                                                  index;
    Opentelemetry__Proto__Profiles__V1development__ProfilesDictionary                      *dictionary;

    dictionary = service_request->dictionary;
    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    if (service_request->resource_profiles != NULL && service_request->n_resource_profiles > 0) {
        for (index = 0;
             result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
             index < service_request->n_resource_profiles;
             index++) {
            result = decode_resource_profiles_entry(context,
                service_request->resource_profiles[index], dictionary);
        }
    }

    return result;
}


int cprof_decode_opentelemetry_create(struct cprof **result_context,
                                      unsigned char *in_buf, size_t in_size,
                                      size_t *offset)
{
    Opentelemetry__Proto__Collector__Profiles__V1development__ExportProfilesServiceRequest *service_request;
    struct cprof                                                                           *context;
    int                                                                                     result;

    result = CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    context = NULL;

    if (result_context != NULL) {
        *result_context = NULL;
    }

    service_request = opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__unpack(
                        NULL,
                        in_size - *offset,
                        &in_buf[*offset]);

    if (service_request != NULL) {
        context = cprof_create();

        if (context != NULL) {
            result = decode_service_request(context, service_request);
        }
        else {
            result = CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        opentelemetry__proto__collector__profiles__v1development__export_profiles_service_request__free_unpacked(service_request, NULL);
    }

    if (result == CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        *result_context = context;
    }
    else if (context != NULL) {
        cprof_destroy(context);
    }

    return result;
}

void cprof_decode_opentelemetry_destroy(struct cprof *context)
{
    if (context != NULL) {
        cprof_destroy(context);
    }
}
