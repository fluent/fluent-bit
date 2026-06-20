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


#include <cprofiles/cprof_decode_msgpack.h>
#include <cprofiles/cprof_variant_utils.h>
#include <cprofiles/cprof_mpack_utils.h>
#include <cfl/cfl_sds.h>

static int unpack_context_header(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {NULL,       NULL}
        };

    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_map(reader,
                                  callbacks,
                                  user_data);
}

static int unpack_resource_attributes(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_resource *resource;
    int                    result;

    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    resource = (struct cprof_resource *) user_data;

    if (resource->attributes != NULL) {
        cfl_kvlist_destroy(resource->attributes);

        resource->attributes = NULL;
    }

    result = unpack_cfl_kvlist(reader, &resource->attributes);

    if (result != 0) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return CPROF_DECODE_MSGPACK_SUCCESS;
}

static int unpack_resource_dropped_attribute_count(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_resource *resource;

    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    resource = (struct cprof_resource *) user_data;

    return cprof_mpack_consume_uint32_tag(reader, &resource->dropped_attributes_count);
}

static int unpack_resource_profiles_entry_resource(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                                     result;
    struct cprof_resource                  *resource;
    struct cprof_resource_profiles         *profiles;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"attributes",              unpack_resource_attributes},
            {"dropped_attribute_count", unpack_resource_dropped_attribute_count},
            {NULL,       NULL}
        };

    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profiles = (struct cprof_resource_profiles *) user_data;

    resource = cprof_resource_create(NULL);

    if (resource == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) resource);

    if (result == CPROF_DECODE_MSGPACK_SUCCESS) {
        if (profiles->resource != NULL) {
            cprof_resource_destroy(profiles->resource);
        }

        profiles->resource = resource;
    }
    else {
        cprof_resource_destroy(resource);
    }

    return result;
}

static int unpack_instrumentation_scope_name(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_instrumentation_scope *instrumentation_scope;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    instrumentation_scope = (struct cprof_instrumentation_scope *) user_data;

    if (instrumentation_scope->name != NULL) {
        cfl_sds_destroy(instrumentation_scope->name);

        instrumentation_scope->name = NULL;
    }

    return cprof_mpack_consume_string_or_nil_tag(reader, &instrumentation_scope->name);
}

static int unpack_instrumentation_scope_version(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_instrumentation_scope *instrumentation_scope;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    instrumentation_scope = (struct cprof_instrumentation_scope *) user_data;

    if (instrumentation_scope->version != NULL) {
        cfl_sds_destroy(instrumentation_scope->version);

        instrumentation_scope->version = NULL;
    }

    return cprof_mpack_consume_string_or_nil_tag(reader, &instrumentation_scope->version);
}

static int unpack_instrumentation_scope_attributes(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_instrumentation_scope *instrumentation_scope;
    int                                 result;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    instrumentation_scope = (struct cprof_instrumentation_scope *) user_data;

    if (instrumentation_scope->attributes != NULL) {
        cfl_kvlist_destroy(instrumentation_scope->attributes);

        instrumentation_scope->attributes = NULL;
    }

    result = unpack_cfl_kvlist(reader, &instrumentation_scope->attributes);

    if (result != 0) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return CPROF_DECODE_MSGPACK_SUCCESS;
}

static int unpack_instrumentation_scope_dropped_attribute_count(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_instrumentation_scope *instrumentation_scope;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    instrumentation_scope = (struct cprof_instrumentation_scope *) user_data;

    return cprof_mpack_consume_uint32_tag(reader, &instrumentation_scope->dropped_attributes_count);
}

static int unpack_scope_profiles_entry_instrumentation_scope(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_instrumentation_scope     *instrumentation_scope;
    struct cprof_scope_profiles            *scope_profiles;
    int                                     result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"name",                    unpack_instrumentation_scope_name},
            {"version",                 unpack_instrumentation_scope_version},
            {"attributes",              unpack_instrumentation_scope_attributes},
            {"dropped_attribute_count", unpack_instrumentation_scope_dropped_attribute_count},
            {NULL,       NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    scope_profiles = (struct cprof_scope_profiles *) user_data;

    instrumentation_scope = cprof_instrumentation_scope_create(NULL, NULL, NULL, 0);

    if (instrumentation_scope == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) instrumentation_scope);

    if (result == CPROF_DECODE_MSGPACK_SUCCESS) {
        if (scope_profiles->scope != NULL) {
            cprof_instrumentation_scope_destroy(scope_profiles->scope);
        }

        scope_profiles->scope = instrumentation_scope;
    }

    if (result != CPROF_DECODE_MSGPACK_SUCCESS) {
        cprof_instrumentation_scope_destroy(instrumentation_scope);
    }

    return result;
}

static int unpack_profile_profile_id(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;
    int                   result;
    cfl_sds_t             value;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    result = cprof_mpack_consume_binary_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        if (cfl_sds_len(value) != sizeof(profile->profile_id)) {
            cfl_sds_destroy(value);

            return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
        }

        memcpy(profile->profile_id,
               value,
               sizeof(profile->profile_id));

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_profile_start_time_unix_nano(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->start_time_unix_nano);
}

static int unpack_profile_end_time_unix_nano(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->end_time_unix_nano);
}

static int unpack_profile_attributes(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;
    int                   result;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (profile->attributes != NULL) {
        cfl_kvlist_destroy(profile->attributes);

        profile->attributes = NULL;
    }

    result = unpack_cfl_kvlist(reader, &profile->attributes);

    if (result != 0) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return CPROF_DECODE_MSGPACK_SUCCESS;
}

static int unpack_profile_dropped_attributes(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_uint32_tag(reader, &profile->dropped_attributes_count);
}

static int unpack_value_type_type(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_value_type *sample_type;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample_type = (struct cprof_value_type *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &sample_type->type);
}

static int unpack_value_type_unit(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_value_type *sample_type;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample_type = (struct cprof_value_type *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &sample_type->unit);
}

static int unpack_value_type_aggregation_temporality(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_value_type *sample_type;
    int                      result;
    uint64_t                 value;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample_type = (struct cprof_value_type *) user_data;

    result = cprof_mpack_consume_uint64_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        sample_type->aggregation_temporality = (int) value;
    }

    return result;
}

static int unpack_profile_sample_types_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_value_type *sample_type;
    struct cprof_profile    *profile;
    int                      result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"type",                    unpack_value_type_type},
            {"unit",                    unpack_value_type_unit},
            {"aggregation_temporality", unpack_value_type_aggregation_temporality},
            {NULL,                    NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    sample_type = cprof_sample_type_create(profile, 0, 0, 0);

    if (sample_type == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) sample_type);

    /* cprof_sample_type_create automatically attaches the newly created
     * instance to the parent profile instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_profile_sample_types(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_sample_types_entry,
                                    user_data);
}

static int unpack_profile_sample_location_index_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (index >= sample->location_index_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_uint64_tag(reader, &sample->location_index[index]);
}

static int unpack_profile_sample_location_index(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                  array_length;
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (sample->location_index != NULL) {
        free(sample->location_index);

        sample->location_index = NULL;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        sample->location_index = calloc(array_length, sizeof(uint64_t));

        if (sample->location_index == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        sample->location_index_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_sample_location_index_entry,
                                    user_data);
}

static int unpack_profile_sample_locations_start_index(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &sample->locations_start_index);
}

static int unpack_profile_sample_locations_length(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &sample->locations_length);
}

static int unpack_profile_sample_values_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (index >= sample->value_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_int64_tag(reader, &sample->values[index]);
}

static int unpack_profile_sample_values(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                  array_length;
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (sample->values != NULL) {
        free(sample->values);

        sample->values = NULL;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        sample->values = calloc(array_length, sizeof(int64_t));

        if (sample->values == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        sample->value_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_sample_values_entry,
                                    user_data);
}

static int unpack_profile_sample_attributes_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (index >= sample->attributes_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_uint64_tag(reader, &sample->attributes[index]);
}

static int unpack_profile_sample_attributes(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                  array_length;
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (sample->attributes != NULL) {
        free(sample->attributes);

        sample->attributes = NULL;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        sample->attributes = calloc(array_length, sizeof(uint64_t));

        if (sample->attributes == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        sample->attributes_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_sample_attributes_entry,
                                    user_data);
}

static int unpack_profile_sample_link(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &sample->link);
}

static int unpack_profile_sample_timestamps_unix_nano_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (index >= sample->timestamps_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_uint64_tag(reader, &sample->timestamps_unix_nano[index]);
}

static int unpack_profile_sample_timestamps_unix_nano(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                  array_length;
    struct cprof_sample *sample;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    sample = (struct cprof_sample *) user_data;

    if (sample->timestamps_unix_nano != NULL) {
        free(sample->timestamps_unix_nano);

        sample->timestamps_unix_nano = NULL;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        sample->timestamps_unix_nano = calloc(array_length, sizeof(uint64_t));

        if (sample->timestamps_unix_nano == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        sample->timestamps_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_sample_timestamps_unix_nano_entry,
                                    user_data);
}

static int unpack_profile_sample_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_sample     *sample;
    struct cprof_profile    *profile;
    int                      result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"location_index",        unpack_profile_sample_location_index},
            {"locations_start_index", unpack_profile_sample_locations_start_index},
            {"locations_length",      unpack_profile_sample_locations_length},
            {"values",                unpack_profile_sample_values},
            {"attributes",            unpack_profile_sample_attributes},
            {"link",                  unpack_profile_sample_link},
            {"timestamps_unix_nano",  unpack_profile_sample_timestamps_unix_nano},
            {NULL,                    NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    sample = cprof_sample_create(profile);

    if (sample == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) sample);

    /* cprof_sample_create automatically attaches the newly created
     * instance to the parent profile instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_profile_sample(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_sample_entry,
                                    user_data);
}





static int unpack_profile_mapping_id(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &mapping->id);
}

static int unpack_profile_mapping_memory_start(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &mapping->memory_start);
}

static int unpack_profile_mapping_memory_limit(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &mapping->memory_limit);
}

static int unpack_profile_mapping_file_offset(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &mapping->file_offset);
}

static int unpack_profile_mapping_filename(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &mapping->filename);
}

static int unpack_profile_mapping_attributes_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    if (index >= mapping->attributes_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_uint64_tag(reader, &mapping->attributes[index]);
}

static int unpack_profile_mapping_attributes(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                  array_length;
    struct cprof_mapping *mapping;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    if (mapping->attributes != NULL) {
        free(mapping->attributes);

        mapping->attributes = NULL;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        mapping->attributes = calloc(array_length, sizeof(uint64_t));

        if (mapping->attributes == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        mapping->attributes_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_mapping_attributes_entry,
                                    user_data);
}

static int unpack_profile_mapping_has_functions(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;
    int                   result;
    uint64_t              value;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    result = cprof_mpack_consume_uint64_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        mapping->has_functions = (bool) value;
    }

    return result;
}

static int unpack_profile_mapping_has_filenames(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;
    int                   result;
    uint64_t              value;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    result = cprof_mpack_consume_uint64_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        mapping->has_filenames = (bool) value;
    }

    return result;
}

static int unpack_profile_mapping_has_line_numbers(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;
    int                   result;
    uint64_t              value;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    result = cprof_mpack_consume_uint64_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        mapping->has_line_numbers = (bool) value;
    }

    return result;
}

static int unpack_profile_mapping_has_inline_frames(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping *mapping;
    int                   result;
    uint64_t              value;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    mapping = (struct cprof_mapping *) user_data;

    result = cprof_mpack_consume_uint64_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        mapping->has_inline_frames = (bool) value;
    }

    return result;
}

static int unpack_profile_mappings_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_mapping    *mapping;
    struct cprof_profile    *profile;
    int                      result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"id",                unpack_profile_mapping_id},
            {"memory_start",      unpack_profile_mapping_memory_start},
            {"memory_limit",      unpack_profile_mapping_memory_limit},
            {"file_offset",       unpack_profile_mapping_file_offset},
            {"filename",          unpack_profile_mapping_filename},
            {"attributes",        unpack_profile_mapping_attributes},
            {"has_functions",     unpack_profile_mapping_has_functions},
            {"has_filenames",     unpack_profile_mapping_has_filenames},
            {"has_line_numbers",  unpack_profile_mapping_has_line_numbers},
            {"has_inline_frames", unpack_profile_mapping_has_inline_frames},
            {NULL,                    NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    mapping = cprof_mapping_create(profile);

    if (mapping == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) mapping);

    /* cprof_mapping_create automatically attaches the newly created
     * instance to the parent profile instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_profile_mappings(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_mappings_entry,
                                    user_data);
}






static int unpack_location_id(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_location *location;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    location = (struct cprof_location *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &location->id);
}

static int unpack_location_mapping_index(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_location *location;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    location = (struct cprof_location *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &location->mapping_index);
}

static int unpack_location_address(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_location *location;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    location = (struct cprof_location *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &location->address);
}







static int unpack_line_function_index(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_line *line;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    line = (struct cprof_line *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &line->function_index);
}

static int unpack_line_line(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_line *line;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    line = (struct cprof_line *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &line->line);
}

static int unpack_line_column(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_line *line;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    line = (struct cprof_line *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &line->column);
}

static int unpack_location_lines_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_location *location;
    struct cprof_line     *line;
    int                    result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"function_index", unpack_line_function_index},
            {"line",           unpack_line_line},
            {"column",         unpack_line_column},
            {NULL,             NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    location = (struct cprof_location *) user_data;

    line = cprof_line_create(location);

    if (line == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) line);

    /* cprof_line_create automatically attaches the newly created
     * instance to the parent location instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_location_lines(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_location_lines_entry,
                                    user_data);
}

static int unpack_location_attributes_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_location *location;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    location = (struct cprof_location *) user_data;

    if (index >= location->attributes_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_uint64_tag(reader, &location->attributes[index]);
}

static int unpack_location_attributes(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                    array_length;
    struct cprof_location *location;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    location = (struct cprof_location *) user_data;

    if (location->attributes != NULL) {
        free(location->attributes);

        location->attributes = NULL;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        location->attributes = calloc(array_length, sizeof(uint64_t));

        if (location->attributes == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        location->attributes_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_location_attributes_entry,
                                    user_data);
}

static int unpack_profile_locations_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_location   *location;
    struct cprof_profile    *profile;
    int                      result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"id",            unpack_location_id},
            {"mapping_index", unpack_location_mapping_index},
            {"address",       unpack_location_address},
            {"lines",         unpack_location_lines},
            {"attributes",    unpack_location_attributes},
            {NULL,            NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    location = cprof_location_create(profile);

    if (location == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) location);

    /* cprof_location_create automatically attaches the newly created
     * instance to the parent profile instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_profile_locations(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_locations_entry,
                                    user_data);
}



static int unpack_profile_location_indices_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile  *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (index >= profile->location_indices_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_int64_tag(reader, &profile->location_indices[index]);
}

static int unpack_profile_location_indices(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                    array_length;
    struct cprof_profile  *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (profile->location_indices != NULL) {
        free(profile->location_indices);

        profile->location_indices = NULL;
        profile->location_indices_count = 0;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        profile->location_indices = calloc(array_length, sizeof(int64_t));

        if (profile->location_indices == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        profile->location_indices_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_location_indices_entry,
                                    user_data);
}






static int unpack_function_id(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_function *function;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    function = (struct cprof_function *) user_data;

    return cprof_mpack_consume_uint64_tag(reader, &function->id);
}

static int unpack_function_name(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_function *function;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    function = (struct cprof_function *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &function->name);
}

static int unpack_function_system_name(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_function *function;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    function = (struct cprof_function *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &function->system_name);
}

static int unpack_function_filename(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_function *function;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    function = (struct cprof_function *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &function->filename);
}

static int unpack_function_start_line(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_function *function;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    function = (struct cprof_function *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &function->start_line);
}

static int unpack_profile_functions_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_function   *function;
    struct cprof_profile    *profile;
    int                      result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"id",            unpack_function_id},
            {"name",          unpack_function_name},
            {"system_name",   unpack_function_system_name},
            {"filename",      unpack_function_filename},
            {"start_line",    unpack_function_start_line},
            {NULL,            NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    function = cprof_function_create(profile);

    if (function == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) function);

    /* cprof_function_create automatically attaches the newly created
     * instance to the parent profile instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_profile_functions(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_functions_entry,
                                    user_data);
}

static int unpack_profile_attribute_table(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile  *profile;
    int                    result;

    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (profile->attribute_table != NULL) {
        cfl_kvlist_destroy(profile->attribute_table);

        profile->attribute_table = NULL;
    }

    result = unpack_cfl_kvlist(reader, &profile->attribute_table);

    if (result != 0) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return CPROF_DECODE_MSGPACK_SUCCESS;
}








static int unpack_profile_attribute_unit_attribute_key(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_attribute_unit *attribute_unit;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    attribute_unit = (struct cprof_attribute_unit *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &attribute_unit->attribute_key);
}

static int unpack_profile_attribute_unit_unit(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_attribute_unit *attribute_unit;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    attribute_unit = (struct cprof_attribute_unit *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &attribute_unit->unit);
}

static int unpack_profile_attribute_units_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_attribute_unit *attribute_unit;
    struct cprof_profile        *profile;
    int                          result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"attribute_key", unpack_profile_attribute_unit_attribute_key},
            {"unit",          unpack_profile_attribute_unit_unit},
            {NULL,            NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    attribute_unit = cprof_attribute_unit_create(profile);

    if (attribute_unit == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) attribute_unit);

    /* cprof_attribute_unit_create automatically attaches the newly created
     * instance to the parent profile instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_profile_attribute_units(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_attribute_units_entry,
                                    user_data);
}


static int unpack_profile_link_trace_id(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_link *link;
    cfl_sds_t          value;
    int                result;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    link = (struct cprof_link *) user_data;

    result = cprof_mpack_consume_binary_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        if (cfl_sds_len(value) != sizeof(link->trace_id)) {
            cfl_sds_destroy(value);

            return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
        }

        memcpy(link->trace_id,
               value,
               sizeof(link->trace_id));

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_profile_link_span_id(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_link *link;
    cfl_sds_t          value;
    int                result;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    link = (struct cprof_link *) user_data;

    result = cprof_mpack_consume_binary_tag(reader, &value);

    if (result == CPROF_MPACK_SUCCESS) {
        if (cfl_sds_len(value) != sizeof(link->span_id)) {
            cfl_sds_destroy(value);

            return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
        }

        memcpy(link->span_id,
               value,
               sizeof(link->span_id));

        cfl_sds_destroy(value);
    }

    return result;
}

static int unpack_profile_link_table_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_link           *link;
    struct cprof_profile        *profile;
    int                          result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"trace_id", unpack_profile_link_trace_id},
            {"span_id",  unpack_profile_link_span_id},
            {NULL,       NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    link = cprof_link_create(profile);

    if (link == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) link);

    /* cprof_link_create automatically attaches the newly created
     * instance to the parent profile instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_profile_link_table(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_link_table_entry,
                                    user_data);
}











static int unpack_profile_string_table_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile  *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (index >= profile->string_table_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_string_tag(reader, &profile->string_table[index]);
}

static int unpack_profile_string_table(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                    array_length;
    struct cprof_profile  *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (profile->string_table != NULL) {
        free(profile->string_table);

        profile->string_table = NULL;
        profile->string_table_count = 0;
        profile->string_table_size = 0;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        profile->string_table = calloc(array_length, sizeof(char *));

        if (profile->string_table == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        profile->string_table_count = (size_t) array_length;
        profile->string_table_size = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_string_table_entry,
                                    user_data);
}



static int unpack_profile_drop_frames(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->drop_frames);
}

static int unpack_profile_keep_frames(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->keep_frames);
}

static int unpack_profile_time_nanos(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->time_nanos);
}

static int unpack_profile_duration_nanos(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->duration_nanos);
}


static int unpack_profile_period_type(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile    *profile;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"type",                    unpack_value_type_type},
            {"unit",                    unpack_value_type_unit},
            {"aggregation_temporality", unpack_value_type_aggregation_temporality},
            {NULL,                    NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_unpack_map(reader,
                                  callbacks,
                                  (void *) &profile->period_type);
}


static int unpack_profile_period(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->period);
}




static int unpack_profile_comments_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile  *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (index >= profile->comments_count) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_consume_int64_tag(reader, &profile->comments[index]);
}

static int unpack_profile_comments(mpack_reader_t *reader, size_t index, void *user_data)
{
    int                    array_length;
    struct cprof_profile  *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    if (profile->comments != NULL) {
        free(profile->comments);

        profile->comments = NULL;
        profile->comments_count = 0;
    }

    array_length = cprof_mpack_peek_array_length(reader);

    if (array_length > 0) {
        profile->comments = calloc(array_length, sizeof(int64_t));

        if (profile->comments == NULL) {
            return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
        }

        profile->comments_count = (size_t) array_length;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_profile_comments_entry,
                                    user_data);
}

static int unpack_profile_default_sample_type(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_profile *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_profile *) user_data;

    return cprof_mpack_consume_int64_tag(reader, &profile->default_sample_type);
}




static int unpack_scope_profiles_entry_profiles_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_scope_profiles *scope_profiles;
    struct cprof_profile        *profile;
    int                          result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"profile_id",           unpack_profile_profile_id},
            {"start_time_unix_nano", unpack_profile_start_time_unix_nano},
            {"end_time_unix_nano",   unpack_profile_end_time_unix_nano},
            {"attributes",           unpack_profile_attributes},
            {"dropped_attributes",   unpack_profile_dropped_attributes},
            {"sample_types",         unpack_profile_sample_types},
            {"sample",               unpack_profile_sample},
            {"mappings",             unpack_profile_mappings},
            {"locations",            unpack_profile_locations},
            {"location_indices",     unpack_profile_location_indices},
            {"functions",            unpack_profile_functions},
            {"attribute_table",      unpack_profile_attribute_table},
            {"attribute_units",      unpack_profile_attribute_units},
            {"link_table",           unpack_profile_link_table},
            {"string_table",         unpack_profile_string_table},
            {"drop_frames",          unpack_profile_drop_frames},
            {"keep_frames",          unpack_profile_keep_frames},
            {"time_nanos",           unpack_profile_time_nanos},
            {"duration_nanos",       unpack_profile_duration_nanos},
            {"period_type",          unpack_profile_period_type},
            {"period",               unpack_profile_period},
            {"comments",             unpack_profile_comments},
            {"default_sample_type",  unpack_profile_default_sample_type},
            {NULL,       NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    scope_profiles = (struct cprof_scope_profiles *) user_data;

    profile = cprof_profile_create();

    if (profile == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) profile);

    if (result == CPROF_DECODE_MSGPACK_SUCCESS) {
        cfl_list_add(&profile->_head, &scope_profiles->profiles);
    }
    else {
        cprof_profile_destroy(profile);
    }

    return result;
}

static int unpack_scope_profiles_entry_profiles(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_scope_profiles_entry_profiles_entry,
                                    user_data);
}


static int unpack_scope_profiles_entry_schema_url(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_scope_profiles *scope_profiles;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    scope_profiles = (struct cprof_scope_profiles *) user_data;

    if (scope_profiles->schema_url != NULL) {
        cfl_sds_destroy(scope_profiles->schema_url);

        scope_profiles->schema_url = NULL;
    }

    return cprof_mpack_consume_string_or_nil_tag(reader, &scope_profiles->schema_url);
}

static int unpack_resource_profiles_entry_scope_profiles_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_resource_profiles *resource_profiles;
    struct cprof_scope_profiles    *scope_profiles;
    int                             result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"instrumentation_scope", unpack_scope_profiles_entry_instrumentation_scope},
            {"profiles",              unpack_scope_profiles_entry_profiles},
            {"schema_url",            unpack_scope_profiles_entry_schema_url},
            {NULL,                    NULL}
        };

    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    resource_profiles = (struct cprof_resource_profiles *) user_data;

    scope_profiles = cprof_scope_profiles_create(resource_profiles, "");

    if (scope_profiles == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) scope_profiles);

    /* cprof_scope_profiles_create automatically attaches the newly created
     * instance to the parent resource cprof profiles instance, because of
     * that in case of failure we just let the parent destructor take care of
     * it.
    */

    return result;
}

static int unpack_resource_profiles_entry_scope_profiles(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_resource_profiles_entry_scope_profiles_entry,
                                    user_data);
}

static int unpack_resource_profiles_entry_schema_url(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_resource_profiles *profile;

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    profile = (struct cprof_resource_profiles *) user_data;

    if (profile->schema_url != NULL) {
        cfl_sds_destroy(profile->schema_url);

        profile->schema_url = NULL;
    }

    return cprof_mpack_consume_string_or_nil_tag(reader, &profile->schema_url);
}

static int unpack_cprof_resource_profiles_entry(mpack_reader_t *reader, size_t index, void *user_data)
{
    struct cprof_resource_profiles *profiles;
    struct cprof                   *context;
    int                             result;
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"resource",       unpack_resource_profiles_entry_resource},
            {"scope_profiles", unpack_resource_profiles_entry_scope_profiles},
            {"schema_url",     unpack_resource_profiles_entry_schema_url},
            {NULL,       NULL}
        };

    if (reader  == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    context = (struct cprof *) user_data;

    profiles = cprof_resource_profiles_create("");

    if (profiles == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    result = cprof_mpack_unpack_map(reader,
                                    callbacks,
                                    (void *) profiles);

    if (result == CPROF_DECODE_MSGPACK_SUCCESS) {
        result = cprof_resource_profiles_add(context, profiles);

        if (result != 0) {
            result = CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
        }
    }

    if (result != CPROF_DECODE_MSGPACK_SUCCESS) {
        cprof_resource_profiles_destroy(profiles);
    }

    return result;
}

static int unpack_context_profiles(mpack_reader_t *reader, size_t index, void *user_data)
{
    if (reader == NULL ||
        user_data == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_array(reader,
                                    unpack_cprof_resource_profiles_entry,
                                    user_data);
}


int unpack_context(struct crof_msgpack_decode_context *context)
{
    struct cprof_mpack_map_entry_callback_t callbacks[] = \
        {
            {"meta",     unpack_context_header},
            {"profiles", unpack_context_profiles},
            {NULL,       NULL}
        };

    if (context == NULL) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    return cprof_mpack_unpack_map(&context->reader,
                                  callbacks,
                                  (void *) context->inner_context);
}

int cprof_decode_msgpack_create(struct cprof **result_context,
                                unsigned char *in_buf,
                                size_t in_size,
                                size_t *offset)
{
    int                                result;
    struct crof_msgpack_decode_context context;
    size_t                             remainder;

    if (result_context == NULL ||
        in_buf == NULL ||
        offset == NULL ||
        in_size < *offset ) {
        return CPROF_DECODE_MSGPACK_INVALID_ARGUMENT_ERROR;
    }

    if (in_size == 0 ||
        (in_size - *offset) == 0) {
        return CPROF_DECODE_MSGPACK_INSUFFICIENT_DATA;
    }

    memset(&context, 0, sizeof(struct crof_msgpack_decode_context));

    context.inner_context = cprof_create();

    if (context.inner_context == NULL) {
        return CPROF_DECODE_MSGPACK_ALLOCATION_ERROR;
    }

    in_size -= *offset;

    mpack_reader_init_data(&context.reader, (const char *) &in_buf[*offset], in_size);

    result = unpack_context(&context);

    remainder = mpack_reader_remaining(&context.reader, NULL);

    *offset += in_size - remainder;

    mpack_reader_destroy(&context.reader);

    if (result != CPROF_DECODE_MSGPACK_SUCCESS) {
        cprof_destroy(context.inner_context);
    }
    else {
        *result_context = context.inner_context;
    }

    return result;
}

void cprof_decode_msgpack_destroy(struct cprof *context)
{
    if (context != NULL) {
        cprof_destroy(context);
    }
}
