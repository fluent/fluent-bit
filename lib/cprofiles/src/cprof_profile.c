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


#include <cprofiles/cprofiles.h>

struct cprof_profile *cprof_profile_create()
{
    struct cprof_profile *profile;

    profile = calloc(1, sizeof(struct cprof_profile));

    if (profile == NULL) {
        return NULL;
    }

    cfl_list_init(&profile->sample_type);
    cfl_list_init(&profile->samples);
    cfl_list_init(&profile->mappings);
    cfl_list_init(&profile->locations);
    cfl_list_init(&profile->functions);
    cfl_list_init(&profile->attribute_units);
    cfl_list_init(&profile->link_table);

    profile->attributes = cfl_kvlist_create();

    if (profile->attributes == NULL) {
        cprof_profile_destroy(profile);

        return NULL;
    }

    profile->attribute_table = cfl_kvlist_create();

    if (profile->attribute_table == NULL) {
        cprof_profile_destroy(profile);

        return NULL;
    }

    return profile;
}

int cprof_profile_add_location_index(struct cprof_profile *profile, int64_t index)
{
    size_t new_size;
    size_t alloc_slots = 32;
    int64_t *reallocated_array;

    if (profile->location_indices == NULL) {
        profile->location_indices = calloc(alloc_slots, sizeof(int64_t));

        if (profile->location_indices == NULL) {
            return -1;
        }

        profile->location_indices_count = 0;
        profile->location_indices_size = alloc_slots;
    }

    if (profile->location_indices_count >= profile->location_indices_size) {
        new_size = profile->location_indices_size + alloc_slots;
        reallocated_array = realloc(profile->location_indices, new_size * sizeof(int64_t));

        if (reallocated_array == NULL) {
            return -1;
        }

        profile->location_indices = reallocated_array;
        profile->location_indices_size = new_size;
    }

    profile->location_indices[profile->location_indices_count] = index;
    profile->location_indices_count++;

    return 0;
}


void cprof_profile_destroy(struct cprof_profile *instance)
{
    struct cfl_list             *iterator_backup;
    struct cprof_attribute_unit *attribute_unit;
    struct cprof_value_type     *value_type;
    struct cprof_location       *location;
    struct cprof_function       *function;
    struct cfl_list             *iterator;
    struct cprof_mapping        *mapping;
    struct cprof_sample         *sample;
    size_t                       index;
    struct cprof_link           *link;

    if (instance->attributes != NULL) {
        cfl_kvlist_destroy(instance->attributes);
    }

    if (instance->original_payload_format != NULL) {
        cfl_sds_destroy(instance->original_payload_format);
    }

    if (instance->original_payload != NULL) {
        cfl_sds_destroy(instance->original_payload);
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &instance->sample_type) {
        value_type = cfl_list_entry(iterator,
                                    struct cprof_value_type,
                                    _head);

        cfl_list_del(&value_type->_head);

        cprof_sample_type_destroy(value_type);
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &instance->samples) {
        sample = cfl_list_entry(iterator,
                                struct cprof_sample,
                                _head);

        cfl_list_del(&sample->_head);

        cprof_sample_destroy(sample);
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &instance->mappings) {
        mapping = cfl_list_entry(iterator,
                                 struct cprof_mapping,
                                 _head);

        cfl_list_del(&mapping->_head);

        cprof_mapping_destroy(mapping);
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &instance->locations) {
        location = cfl_list_entry(iterator,
                                  struct cprof_location,
                                  _head);

        cfl_list_del(&location->_head);

        cprof_location_destroy(location);
    }

    if (instance->location_indices != NULL) {
        free(instance->location_indices);
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &instance->functions) {
        function = cfl_list_entry(iterator,
                                  struct cprof_function,
                                  _head);

        cfl_list_del(&function->_head);

        cprof_function_destroy(function);
    }

    if (instance->attribute_table != NULL) {
        cfl_kvlist_destroy(instance->attribute_table);
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &instance->attribute_units) {
        attribute_unit = cfl_list_entry(iterator,
                                        struct cprof_attribute_unit,
                                        _head);

        cfl_list_del(&attribute_unit->_head);

        cprof_attribute_unit_destroy(attribute_unit);
    }

    cfl_list_foreach_safe(iterator,
                          iterator_backup,
                          &instance->link_table) {
        link = cfl_list_entry(iterator,
                              struct cprof_link,
                              _head);

        cfl_list_del(&link->_head);

        cprof_link_destroy(link);
    }

    if (instance->string_table != NULL) {
        for (index = 0 ; index < instance->string_table_count ; index++) {
            cfl_sds_destroy(instance->string_table[index]);
        }

        free(instance->string_table);
    }

    if (instance->comments != NULL) {
        free(instance->comments);
    }

    free(instance);
}

size_t cprof_profile_string_add(struct cprof_profile *profile, char *str, int str_len)
{
    int alloc_size = 64;
    size_t id;
    size_t new_size;
    cfl_sds_t *new_table;

    if (!str) {
        return -1;
    }

    if (str_len <= 0) {
        str_len = strlen(str);
    }

    if (!profile->string_table && str_len > 0) {
        profile->string_table = malloc(alloc_size * sizeof(cfl_sds_t));
        if (!profile->string_table) {
            return -1;
        }
        profile->string_table_size = alloc_size;

        /* string_table[0] must always be "" */
        profile->string_table[0] = cfl_sds_create_len("", 0);
        if (!profile->string_table[0]) {
            return -1;
        }
        profile->string_table_count = 1;
    }

    /* check there is enough room for a new entry */
    if (profile->string_table_count >= profile->string_table_size) {
        new_size = profile->string_table_size + alloc_size;
        new_table = realloc(profile->string_table, new_size * sizeof(cfl_sds_t));
        if (!new_table) {
            return -1;
        }
        profile->string_table = new_table;
        profile->string_table_size = new_size;
    }

    id = profile->string_table_count;
    profile->string_table[id] = cfl_sds_create_len(str, str_len);
    if (!profile->string_table[id]) {
        return -1;
    }
    profile->string_table_count++;

    return id;
}

int cprof_profile_add_comment(struct cprof_profile *profile, int64_t comment)
{
    size_t new_size;
    size_t alloc_slots = 32;
    int64_t *reallocated_array;

    if (profile->comments == NULL) {
        profile->comments = calloc(alloc_slots, sizeof(int64_t));

        if (profile->comments == NULL) {
            return -1;
        }

        profile->comments_count = 0;
        profile->comments_size = alloc_slots;
    }

    if (profile->comments_count >= profile->comments_size) {
        new_size = profile->comments_size + alloc_slots;
        reallocated_array = realloc(profile->comments, new_size * sizeof(int64_t));

        if (reallocated_array == NULL) {
            return -1;
        }

        profile->comments = reallocated_array;
        profile->comments_size = new_size;
    }

    profile->comments[profile->comments_count] = comment;
    profile->comments_count++;

    return 0;
}
