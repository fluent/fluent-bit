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


#include <cprofiles/cprof_encode_msgpack.h>
#include <cprofiles/cprof_variant_utils.h>

static inline void mpack_write_sds_or_nil(mpack_writer_t *writer,
                                          cfl_sds_t value)
{
    if (value != NULL) {
        mpack_write_str(writer,
                        value,
                        cfl_sds_len(value));
    }
    else {
        mpack_write_nil(writer);
    }
}

static int encode_string_array(
                struct cprof_msgpack_encoding_context *context,
                char **data_list,
                size_t data_length);

static int encode_uint64_t_array(
                struct cprof_msgpack_encoding_context *context,
                uint64_t *data_list,
                size_t data_length);

static int encode_int64_t_array(
                struct cprof_msgpack_encoding_context *context,
                int64_t *data_list,
                size_t data_length);

static int encode_cprof_value_type(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_value_type *instance);

static int encode_cprof_sample(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_sample *instance);

static int encode_cprof_mapping(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_mapping *instance);

static int encode_cprof_line(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_line *instance);

static int encode_cprof_location(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_location *instance);

static int encode_cprof_function(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_function *instance);

static int encode_cprof_attribute_unit(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_attribute_unit *instance);


static int encode_cprof_link(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_link *instance);


static int encode_cprof_profile(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_profile *instance);


static int encode_cprof_resource_profiles(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_resource_profiles *instance);


static int encode_cprof_instrumentation_scope(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_instrumentation_scope *instance);


static int encode_cprof_resource(
            struct cprof_msgpack_encoding_context *context,
            struct cprof_resource *instance);


static int encode_cprof_scope_profiles(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_scope_profiles *instance);


static int encode_string_array(
                struct cprof_msgpack_encoding_context *context,
                char **data_list,
                size_t data_length)
{
    size_t index;

    mpack_start_array(&context->writer,
                      data_length);

    for (index = 0 ; index < data_length ; index++) {
        mpack_write_cstr(&context->writer, data_list[index]);
    }

    mpack_finish_array(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int encode_uint64_t_array(
                struct cprof_msgpack_encoding_context *context,
                uint64_t *data_list,
                size_t data_length)
{
    size_t index;

    mpack_start_array(&context->writer,
                      data_length);

    for (index = 0 ; index < data_length ; index++) {
        mpack_write_u64(&context->writer, data_list[index]);
    }

    mpack_finish_array(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int encode_int64_t_array(
                struct cprof_msgpack_encoding_context *context,
                int64_t *data_list,
                size_t data_length)
{
    size_t index;

    mpack_start_array(&context->writer,
                      data_length);

    for (index = 0 ; index < data_length ; index++) {
        mpack_write_i64(&context->writer, data_list[index]);
    }

    mpack_finish_array(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}


static int encode_cprof_value_type(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_value_type *instance) {
    mpack_start_map(&context->writer, 3);

    mpack_write_cstr(&context->writer, "type");
    mpack_write_i64(&context->writer, instance->type);

    mpack_write_cstr(&context->writer, "unit");
    mpack_write_i64(&context->writer, instance->unit);

    mpack_write_cstr(&context->writer, "aggregation_temporality");
    mpack_write_u64(&context->writer, instance->aggregation_temporality);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int encode_cprof_sample(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_sample *instance) {
    int result;

    mpack_start_map(&context->writer, 7);

    mpack_write_cstr(&context->writer, "location_index");

    result = encode_uint64_t_array(context,
                                   instance->location_index,
                                   instance->location_index_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "locations_start_index");
    mpack_write_u64(&context->writer, instance->locations_start_index);

    mpack_write_cstr(&context->writer, "locations_length");
    mpack_write_u64(&context->writer, instance->locations_length);

    mpack_write_cstr(&context->writer, "values");
    result = encode_int64_t_array(context,
                                  instance->values,
                                  instance->value_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "attributes");
    result = encode_uint64_t_array(context,
                                   instance->attributes,
                                   instance->attributes_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "link");
    mpack_write_u64(&context->writer, instance->link);

    mpack_write_cstr(&context->writer, "timestamps_unix_nano");
    result = encode_uint64_t_array(context,
                                   instance->timestamps_unix_nano,
                                   instance->timestamps_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int encode_cprof_mapping(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_mapping *instance) {
    int result;

    mpack_start_map(&context->writer, 10);

    mpack_write_cstr(&context->writer, "id");
    mpack_write_u64(&context->writer, instance->id);

    mpack_write_cstr(&context->writer, "memory_start");
    mpack_write_u64(&context->writer, instance->memory_start);

    mpack_write_cstr(&context->writer, "memory_limit");
    mpack_write_u64(&context->writer, instance->memory_limit);

    mpack_write_cstr(&context->writer, "file_offset");
    mpack_write_u64(&context->writer, instance->file_offset);

    mpack_write_cstr(&context->writer, "filename");
    mpack_write_i64(&context->writer, instance->filename);

    mpack_write_cstr(&context->writer, "attributes");
    result = encode_uint64_t_array(context,
                                   instance->attributes,
                                   instance->attributes_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "has_functions");
    mpack_write_u64(&context->writer, instance->has_functions);

    mpack_write_cstr(&context->writer, "has_filenames");
    mpack_write_u64(&context->writer, instance->has_filenames);

    mpack_write_cstr(&context->writer, "has_line_numbers");
    mpack_write_u64(&context->writer, instance->has_line_numbers);

    mpack_write_cstr(&context->writer, "has_inline_frames");
    mpack_write_u64(&context->writer, instance->has_inline_frames);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}





static int encode_cprof_line(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_line *instance) {
    mpack_start_map(&context->writer, 3);

    mpack_write_cstr(&context->writer, "function_index");
    mpack_write_u64(&context->writer, instance->function_index);

    mpack_write_cstr(&context->writer, "line");
    mpack_write_i64(&context->writer, instance->line);

    mpack_write_cstr(&context->writer, "column");
    mpack_write_i64(&context->writer, instance->column);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}



static int encode_cprof_location(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_location *instance) {
    struct cfl_list   *iterator;
    int                result;
    struct cprof_line *line;

    mpack_start_map(&context->writer, 5);

    mpack_write_cstr(&context->writer, "id");
    mpack_write_u64(&context->writer, instance->id);

    mpack_write_cstr(&context->writer, "mapping_index");
    mpack_write_u64(&context->writer, instance->mapping_index);

    mpack_write_cstr(&context->writer, "address");
    mpack_write_u64(&context->writer, instance->address);

    mpack_write_cstr(&context->writer, "lines");
    mpack_start_array(&context->writer, cfl_list_size(&instance->lines));

    if (!cfl_list_is_empty(&instance->lines)) {
        cfl_list_foreach(iterator,
                        &instance->lines) {
            line = cfl_list_entry(iterator,
                                struct cprof_line, _head);

            result = encode_cprof_line(context, line);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "attributes");

    result = encode_uint64_t_array(context,
                                   instance->attributes,
                                   instance->attributes_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}




static int encode_cprof_function(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_function *instance) {
    mpack_start_map(&context->writer, 5);

    mpack_write_cstr(&context->writer, "id");
    mpack_write_u64(&context->writer, instance->id);

    mpack_write_cstr(&context->writer, "name");
    mpack_write_i64(&context->writer, instance->name);

    mpack_write_cstr(&context->writer, "system_name");
    mpack_write_i64(&context->writer, instance->system_name);

    mpack_write_cstr(&context->writer, "filename");
    mpack_write_i64(&context->writer, instance->filename);

    mpack_write_cstr(&context->writer, "start_line");
    mpack_write_i64(&context->writer, instance->start_line);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}




static int encode_cprof_attribute_unit(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_attribute_unit *instance) {
    mpack_start_map(&context->writer, 2);

    mpack_write_cstr(&context->writer, "attribute_key");
    mpack_write_i64(&context->writer, instance->attribute_key);

    mpack_write_cstr(&context->writer, "unit");
    mpack_write_i64(&context->writer, instance->unit);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int encode_cprof_link(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_link *instance)
{
    mpack_start_map(&context->writer, 2);

    mpack_write_cstr(&context->writer, "trace_id");
    mpack_write_bin(&context->writer,
                    (const char *) instance->trace_id,
                    sizeof(instance->trace_id));

    mpack_write_cstr(&context->writer, "span_id");
    mpack_write_bin(&context->writer,
                    (const char *) instance->span_id,
                    sizeof(instance->span_id));

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}


static int encode_cprof_profile(
                struct cprof_msgpack_encoding_context *context,
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


    mpack_start_map(&context->writer, 23);

    mpack_write_cstr(&context->writer, "profile_id");
    mpack_write_bin(&context->writer,
                    (const char *) instance->profile_id,
                    sizeof(instance->profile_id));

    mpack_write_cstr(&context->writer, "start_time_unix_nano");
    mpack_write_i64(&context->writer, instance->start_time_unix_nano);

    mpack_write_cstr(&context->writer, "end_time_unix_nano");
    mpack_write_i64(&context->writer, instance->end_time_unix_nano);

    mpack_write_cstr(&context->writer, "attributes");

    result = pack_cfl_variant_kvlist(&context->writer,
                                     instance->attributes);

    if (result != 0) {
        return -1;
    }

    mpack_write_cstr(&context->writer, "dropped_attributes");
    mpack_write_u32(&context->writer,
                    instance->dropped_attributes_count);

    mpack_write_cstr(&context->writer, "sample_types");

    mpack_start_array(&context->writer, cfl_list_size(&instance->sample_type));

    if (!cfl_list_is_empty(&instance->sample_type)) {
        cfl_list_foreach(iterator,
                        &instance->sample_type) {
            sample_type = cfl_list_entry(
                            iterator,
                            struct cprof_value_type, _head);

            result = encode_cprof_value_type(context, sample_type);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "sample");

    mpack_start_array(&context->writer, cfl_list_size(&instance->samples));

    if (!cfl_list_is_empty(&instance->samples)) {
        cfl_list_foreach(iterator,
                        &instance->samples) {
            sample = cfl_list_entry(
                        iterator,
                        struct cprof_sample, _head);

            result = encode_cprof_sample(context, sample);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "mappings");

    mpack_start_array(&context->writer, cfl_list_size(&instance->mappings));

    if (!cfl_list_is_empty(&instance->mappings)) {
        cfl_list_foreach(iterator,
                        &instance->mappings) {
            mapping = cfl_list_entry(
                        iterator,
                        struct cprof_mapping, _head);

            result = encode_cprof_mapping(context, mapping);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "locations");

    mpack_start_array(&context->writer, cfl_list_size(&instance->locations));

    if (!cfl_list_is_empty(&instance->locations)) {
        cfl_list_foreach(iterator,
                        &instance->locations) {
            location = cfl_list_entry(
                        iterator,
                        struct cprof_location, _head);

            result = encode_cprof_location(context, location);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "location_indices");

    result = encode_int64_t_array(context,
                                  instance->location_indices,
                                  instance->location_indices_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "functions");

    mpack_start_array(&context->writer, cfl_list_size(&instance->functions));

    if (!cfl_list_is_empty(&instance->functions)) {
        cfl_list_foreach(iterator,
                        &instance->functions) {
            function = cfl_list_entry(
                        iterator,
                        struct cprof_function, _head);

            result = encode_cprof_function(context, function);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "attribute_table");

    result = pack_cfl_variant_kvlist(&context->writer,
                                     instance->attribute_table);

    if (result != 0) {
        return -1;
    }

    mpack_write_cstr(&context->writer, "attribute_units");

    mpack_start_array(&context->writer, cfl_list_size(&instance->attribute_units));

    if (!cfl_list_is_empty(&instance->attribute_units)) {
        cfl_list_foreach(iterator,
                         &instance->attribute_units) {
            attribute_unit = cfl_list_entry(
                                iterator,
                                struct cprof_attribute_unit, _head);

            result = encode_cprof_attribute_unit(context, attribute_unit);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "link_table");

    mpack_start_array(&context->writer, cfl_list_size(&instance->link_table));

    if (!cfl_list_is_empty(&instance->link_table)) {
        cfl_list_foreach(iterator,
                         &instance->link_table) {
            link = cfl_list_entry(
                    iterator,
                    struct cprof_link, _head);

            result = encode_cprof_link(context, link);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "string_table");

    result = encode_string_array(
                context,
                (char **) instance->string_table,
                instance->string_table_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "drop_frames");
    mpack_write_i64(&context->writer, instance->drop_frames);

    mpack_write_cstr(&context->writer, "keep_frames");
    mpack_write_i64(&context->writer, instance->keep_frames);

    mpack_write_cstr(&context->writer, "time_nanos");
    mpack_write_i64(&context->writer, instance->time_nanos);

    mpack_write_cstr(&context->writer, "duration_nanos");
    mpack_write_i64(&context->writer, instance->duration_nanos);

    mpack_write_cstr(&context->writer, "period_type");
    result = encode_cprof_value_type(context, &instance->period_type);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "period");
    mpack_write_i64(&context->writer, instance->period);

    mpack_write_cstr(&context->writer, "comments");
    result = encode_int64_t_array(context,
                                  instance->comments,
                                  instance->comments_count);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "default_sample_type");
    mpack_write_i64(&context->writer, instance->default_sample_type);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int encode_cprof_resource_profiles(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_resource_profiles *instance) {
    int                          result;
    struct cfl_list             *iterator;
    struct cprof_scope_profiles *scope_profile;

    mpack_start_map(&context->writer, 3);
    mpack_write_cstr(&context->writer, "resource");

    result = encode_cprof_resource(context, instance->resource);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "scope_profiles");

    mpack_start_array(&context->writer, cfl_list_size(&instance->scope_profiles));

    if (!cfl_list_is_empty(&instance->scope_profiles)) {
        cfl_list_foreach(iterator,
                         &instance->scope_profiles) {
            scope_profile = cfl_list_entry(
                                iterator,
                                struct cprof_scope_profiles, _head);

            result = encode_cprof_scope_profiles(context, scope_profile);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "schema_url");

    mpack_write_sds_or_nil(&context->writer,
                           instance->schema_url);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int encode_cprof_instrumentation_scope(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_instrumentation_scope *instance) {
    int result;

    mpack_start_map(&context->writer, 4);

    mpack_write_cstr(&context->writer, "name");
    mpack_write_sds_or_nil(&context->writer,
                           instance->name);


    mpack_write_cstr(&context->writer, "version");
    mpack_write_sds_or_nil(&context->writer,
                           instance->version);


    mpack_write_cstr(&context->writer, "attributes");

    result = pack_cfl_variant_kvlist(&context->writer,
                                     instance->attributes);

    if (result != 0) {
        return -1;
    }

    mpack_write_cstr(&context->writer, "dropped_attribute_count");
    mpack_write_u32(&context->writer, instance->dropped_attributes_count);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}



static int encode_cprof_resource(
            struct cprof_msgpack_encoding_context *context,
            struct cprof_resource *instance) {
    int result;

    mpack_start_map(&context->writer, 2);

    mpack_write_cstr(&context->writer, "attributes");

    result = pack_cfl_variant_kvlist(&context->writer,
                                     instance->attributes);

    if (result != 0) {
        return -1;
    }

    mpack_write_cstr(&context->writer, "dropped_attribute_count");
    mpack_write_u32(&context->writer, instance->dropped_attributes_count);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}





static int encode_cprof_scope_profiles(
                struct cprof_msgpack_encoding_context *context,
                struct cprof_scope_profiles *instance) {
    int                   result;
    struct cfl_list      *iterator;
    struct cprof_profile *profile;

    mpack_start_map(&context->writer, 3);
    mpack_write_cstr(&context->writer, "instrumentation_scope");

    result = encode_cprof_instrumentation_scope(context, instance->scope);

    if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
        return result;
    }

    mpack_write_cstr(&context->writer, "profiles");

    mpack_start_array(&context->writer, cfl_list_size(&instance->profiles));

    if (!cfl_list_is_empty(&instance->profiles)) {
        cfl_list_foreach(iterator,
                         &instance->profiles) {
            profile = cfl_list_entry(
                        iterator,
                        struct cprof_profile, _head);

            result = encode_cprof_profile(context, profile);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    mpack_write_cstr(&context->writer, "schema_url");

    mpack_write_sds_or_nil(&context->writer,
                           instance->schema_url);

    mpack_finish_map(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int pack_context_header(struct cprof_msgpack_encoding_context *context,
                               struct cprof *profile)
{
    mpack_write_cstr(&context->writer, "meta");
    mpack_start_map(&context->writer, 0);
    mpack_finish_map(&context->writer);

    return 0;
}

static int pack_context_profiles(struct cprof_msgpack_encoding_context *context,
                                 struct cprof *profile)
{
    int                             result;
    struct cfl_list                *iterator;
    size_t                          profile_count;
    struct cprof_resource_profiles *resource_profiles;

    profile_count = 0 ;
    profile_count = cfl_list_size(&profile->profiles);

    mpack_write_cstr(&context->writer, "profiles");
    mpack_start_array(&context->writer, profile_count);

    if (!cfl_list_is_empty(&profile->profiles)) {
        cfl_list_foreach(iterator,
                         &profile->profiles) {
            resource_profiles = cfl_list_entry(
                                    iterator,
                                    struct cprof_resource_profiles, _head);

            result = encode_cprof_resource_profiles(context, resource_profiles);

            if (result != CPROF_ENCODE_MSGPACK_SUCCESS) {
                return result;
            }
        }
    }

    mpack_finish_array(&context->writer);

    return CPROF_ENCODE_MSGPACK_SUCCESS;
}

static int pack_context(struct cprof_msgpack_encoding_context *context,
                        struct cprof *profile)
{
    int result;

    mpack_start_map(&context->writer, 2);

    result = pack_context_header(context, profile);

    if (result != 0) {
        return -1;
    }

    result = pack_context_profiles(context, profile);

    if (result != 0) {
        return -2;
    }

    mpack_finish_map(&context->writer); /* outermost context scope */

    return 0;
}

int cprof_encode_msgpack_create(cfl_sds_t *result_buffer,
                                struct cprof *profile)
{
    int                                   result;
    struct cprof_msgpack_encoding_context context;

    *result_buffer = NULL;

    memset(&context, 0, sizeof(context));

    mpack_writer_init_growable(&context.writer,
                               &context.output_buffer,
                               &context.output_size);


    result = pack_context(&context, profile);

    if (mpack_writer_destroy(&context.writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
    }

    if (result == CPROF_ENCODE_MSGPACK_SUCCESS) {
        *result_buffer = cfl_sds_create_len(context.output_buffer, context.output_size);
    }

    if (context.output_buffer != NULL) {
        free(context.output_buffer);
    }

    return result;
}

void cprof_encode_msgpack_destroy(cfl_sds_t instance)
{
    if (instance != NULL) {
        cfl_sds_destroy(instance);
    }
}
