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
    Opentelemetry__Proto__Profiles__V1development__Sample *input_sample)
{
    int    result;
    size_t index;

    for (index = 0 ;
         index < input_sample->n_location_index;
         index++) {

        result = cprof_sample_add_location_index(sample, input_sample->location_index[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_sample->n_value;
         index++) {

        result = cprof_sample_add_value(sample, input_sample->value[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_sample->n_attributes;
         index++) {

        result = cprof_sample_add_attribute(sample, input_sample->attributes[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_sample->n_timestamps_unix_nano;
         index++) {

        result = cprof_sample_add_timestamp(sample, input_sample->timestamps_unix_nano[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    sample->locations_start_index = input_sample->locations_start_index;
    sample->locations_length = input_sample->locations_length;
    sample->link = input_sample->link;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}




static int decode_mapping_entry(struct cprof_mapping *mapping,
    Opentelemetry__Proto__Profiles__V1development__Mapping *input_mapping)
{
    int    result;
    size_t index;

    for (index = 0 ;
         index < input_mapping->n_attributes;
         index++) {

        result = cprof_mapping_add_attribute(mapping, input_mapping->attributes[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    mapping->id = input_mapping->id;
    mapping->memory_start = input_mapping->memory_start;
    mapping->memory_limit = input_mapping->memory_limit;
    mapping->file_offset = input_mapping->file_offset;
    mapping->filename = input_mapping->filename;

    mapping->has_functions = input_mapping->has_functions;
    mapping->has_filenames = input_mapping->has_filenames;
    mapping->has_line_numbers = input_mapping->has_line_numbers;
    mapping->has_inline_frames = input_mapping->has_inline_frames;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_line_entry(struct cprof_line *line,
    Opentelemetry__Proto__Profiles__V1development__Line *input_line)
{
    line->function_index = input_line->function_index;
    line->line = input_line->line;
    line->column = input_line->column;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_location_entry(struct cprof_location *location,
    Opentelemetry__Proto__Profiles__V1development__Location *input_location)

{
    int                result;
    size_t             index;
    struct cprof_line *line;

    location->id = input_location->id;
    location->mapping_index = input_location->mapping_index;
    location->address = input_location->address;

    for (index = 0 ;
         index < input_location->n_line ;
         index++) {
        line = cprof_line_create(location);

        if (line == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_line_entry(line,
                                   input_location->line[index]);

        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    location->is_folded = input_location->is_folded;

    for (index = 0 ;
         index < input_location->n_attributes;
         index++) {

        result = cprof_location_add_attribute(location, input_location->attributes[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_function_entry(struct cprof_function *function,
    Opentelemetry__Proto__Profiles__V1development__Function *input_function)
{
    function->id = input_function->id;
    function->name = input_function->name;
    function->system_name = input_function->system_name;
    function->filename = input_function->filename;
    function->start_line = input_function->start_line;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_attribute_unit_entry(struct cprof_attribute_unit *attribute_unit,
    Opentelemetry__Proto__Profiles__V1development__AttributeUnit *input_attribute_unit)
{
    attribute_unit->attribute_key = input_attribute_unit->attribute_key;
    attribute_unit->unit = input_attribute_unit->unit;

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
    Opentelemetry__Proto__Profiles__V1development__Profile *input_profile)
{
    size_t                       string_table_add_result;
    struct cprof_attribute_unit *attribute_unit;
    struct cprof_value_type     *sample_type;
    struct cprof_location       *location;
    struct cprof_function       *function;
    struct cprof_mapping        *mapping;
    struct cprof_sample         *sample;
    int                          result;
    size_t                       index;
    struct cprof_link           *link;

    for (index = 0 ;
         index < input_profile->n_sample_type ;
         index++) {
        sample_type = cprof_sample_type_create(
                        profile,
                        input_profile->sample_type[index]->type,
                        input_profile->sample_type[index]->unit,
                        input_profile->sample_type[index]->aggregation_temporality);

        if (sample_type == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_sample ;
         index++) {
        sample = cprof_sample_create(profile);

        if (sample == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_profile_sample_entry(sample,
                                             input_profile->sample[index]);

        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_mapping;
         index++) {
        mapping = cprof_mapping_create(profile);

        if (mapping == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_mapping_entry(mapping,
                                      input_profile->mapping[index]);

        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_location;
         index++) {
        location = cprof_location_create(profile);

        if (location == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_location_entry(location,
                                       input_profile->location[index]);

        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_location_indices;
         index++) {

        result = cprof_profile_add_location_index(profile, input_profile->location_indices[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_function;
         index++) {
        function = cprof_function_create(profile);

        if (function == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_function_entry(function,
                                       input_profile->function[index]);

        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    result = convert_kvarray_to_kvlist(profile->attribute_table,
                                       input_profile->attribute_table,
                                       input_profile->n_attribute_table);

    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    for (index = 0 ;
         index < input_profile->n_attribute_units;
         index++) {
        attribute_unit = cprof_attribute_unit_create(profile);

        if (attribute_unit == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_attribute_unit_entry(attribute_unit,
                                             input_profile->attribute_units[index]);

        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_link_table;
         index++) {
        link = cprof_link_create(profile);

        if (link == NULL) {
            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }

        result = decode_link_table_entry(link,
                                         input_profile->link_table[index]);

        if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_string_table;
         index++) {
        string_table_add_result = cprof_profile_string_add(
                                    profile,
                                    input_profile->string_table[index],
                                    strlen(input_profile->string_table[index]));

        if (string_table_add_result == -1) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    for (index = 0 ;
         index < input_profile->n_comment;
         index++) {
        result = cprof_profile_add_comment(
                    profile,
                    input_profile->comment[index]);

        if (result != 0) {
            return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
        }
    }

    profile->drop_frames = input_profile->drop_frames;
    profile->keep_frames = input_profile->keep_frames;

    profile->time_nanos = input_profile->time_nanos;
    profile->duration_nanos = input_profile->duration_nanos;

    if (input_profile->period_type != NULL) {
        profile->period_type.type = input_profile->period_type->type;
        profile->period_type.unit = input_profile->period_type->unit;
        profile->period_type.aggregation_temporality = input_profile->period_type->aggregation_temporality;
    }

    profile->period = input_profile->period;
    profile->default_sample_type = input_profile->default_sample_type;

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_profile_container_entry(struct cprof_scope_profiles *scope_profiles,
    Opentelemetry__Proto__Profiles__V1development__ProfileContainer *input_profile_container)
{
    struct cprof_profile    *profile;
    int                      result;

    if (input_profile_container->profile_id.data == NULL ||
        input_profile_container->profile_id.len != 16) {
        return CPROF_DECODE_OPENTELEMETRY_INVALID_ARGUMENT_ERROR;
    }

    profile = cprof_profile_create();

    if (profile == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    memcpy(profile->profile_id,
           input_profile_container->profile_id.data,
           sizeof(profile->profile_id));

    profile->start_time_unix_nano = input_profile_container->start_time_unix_nano;
    profile->end_time_unix_nano = input_profile_container->end_time_unix_nano;


    result = convert_kvarray_to_kvlist(profile->attributes,
                                       input_profile_container->attributes,
                                       input_profile_container->n_attributes);

    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        cprof_profile_destroy(profile);

        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    profile->dropped_attributes_count = input_profile_container->dropped_attributes_count;

    if (input_profile_container->original_payload_format != NULL) {
        profile->original_payload_format = cfl_sds_create(input_profile_container->original_payload_format);

        if (profile->original_payload_format == NULL) {
            cprof_profile_destroy(profile);

            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    if (input_profile_container->original_payload.data != NULL &&
        input_profile_container->original_payload.len > 0) {
        profile->original_payload = \
            cfl_sds_create_len(
                (const char *) input_profile_container->original_payload.data,
                input_profile_container->original_payload.len);

        if (profile->original_payload == NULL) {
            cprof_profile_destroy(profile);

            return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
        }
    }

    result = decode_profile_entry(
                profile,
                input_profile_container->profile);

    if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
        return result;
    }

    cfl_list_add(&profile->_head, &scope_profiles->profiles);

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}


static int decode_scope_profiles_entry(struct cprof_resource_profiles *resource_profiles,
    Opentelemetry__Proto__Profiles__V1development__ScopeProfiles *input_scope_profiles)
{
    struct cprof_scope_profiles *profiles;
    int                          result;
    size_t                       index;

    profiles = cprof_scope_profiles_create(
                    resource_profiles,
                    input_scope_profiles->schema_url);

    if (profiles == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    profiles->scope = decode_instrumentation_scope(input_scope_profiles->scope);

    if (profiles->scope == NULL) {
        cprof_scope_profiles_destroy(profiles);

        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    if (input_scope_profiles->n_profiles > 0) {
        for (index = 0 ;
             index < input_scope_profiles->n_profiles ;
             index++) {
            result = decode_profile_container_entry(
                        profiles,
                        input_scope_profiles->profiles[index]);

            if (result != CPROF_DECODE_OPENTELEMETRY_SUCCESS) {
                cprof_scope_profiles_destroy(profiles);

                return result;
            }
        }
    }

    return CPROF_DECODE_OPENTELEMETRY_SUCCESS;
}

static int decode_resource_profiles_entry(struct cprof *context,
    Opentelemetry__Proto__Profiles__V1development__ResourceProfiles *resource_profile)
{
    struct cprof_resource_profiles *profile;
    int                             result;
    size_t                          index;

    profile = cprof_resource_profiles_create(resource_profile->schema_url);

    if (profile == NULL) {
        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    profile->resource = decode_resource(resource_profile->resource);

    if (profile->resource == NULL) {
        cprof_resource_profiles_destroy(profile);

        return CPROF_DECODE_OPENTELEMETRY_ALLOCATION_ERROR;
    }

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    if (resource_profile->n_scope_profiles > 0) {
        for (index = 0 ;
             result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
             index < resource_profile->n_scope_profiles ;
             index++) {

            result = decode_scope_profiles_entry(
                        profile,
                        resource_profile->scope_profiles[index]);
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
    int    result;
    size_t index;

    result = CPROF_DECODE_OPENTELEMETRY_SUCCESS;

    if (service_request->n_resource_profiles > 0) {
        for (index = 0 ;
             result == CPROF_DECODE_OPENTELEMETRY_SUCCESS &&
             index < service_request->n_resource_profiles ;
             index++) {

            result = decode_resource_profiles_entry(
                        context,
                        service_request->resource_profiles[index]);
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

    return result;
}

void cprof_decode_opentelemetry_destroy(struct cprof *context)
{
    if (context != NULL) {
        cprof_destroy(context);
    }
}