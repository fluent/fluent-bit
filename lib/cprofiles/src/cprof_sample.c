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

struct cprof_sample *cprof_sample_create(struct cprof_profile *profile)
{
    struct cprof_sample *sample;

    sample = calloc(1, sizeof(struct cprof_sample));
    if (!sample) {
        return NULL;
    }

    cfl_list_add(&sample->_head, &profile->samples);
    return sample;
}

int cprof_sample_add_location_index(struct cprof_sample *sample, uint64_t location_index)
{
    size_t new_size;
    size_t alloc_slots = 32;
    uint64_t *reallocated_location_index;

    if (sample->location_index == NULL) {
        sample->location_index = calloc(1, alloc_slots * sizeof(uint64_t));

        if (sample->location_index == NULL) {
            return -1;
        }

        sample->location_index_count = 0;
        sample->location_index_size = alloc_slots;
    }

    /* check if we have space in the location index by checking location_index_size */
    if (sample->location_index_count >= sample->location_index_size) {
        new_size = sample->location_index_size + alloc_slots;
        reallocated_location_index = realloc(sample->location_index, new_size * sizeof(uint64_t));

        if (reallocated_location_index == NULL) {
            return -1;
        }

        sample->location_index = reallocated_location_index;
        sample->location_index_size = new_size;
    }

    /* add the location */
    sample->location_index[sample->location_index_count] = location_index;
    sample->location_index_count++;

    return 0;
}

int cprof_sample_add_value(struct cprof_sample *sample, int64_t value)
{
    size_t new_size;
    size_t alloc_slots = 32;
    int64_t *reallocated_values;

    if (sample->values == NULL) {
        sample->values = calloc(alloc_slots, sizeof(int64_t));

        if (sample->values == NULL) {
            return -1;
        }

        sample->value_count = 0;
        sample->value_size = alloc_slots;
    }

    if (sample->value_count >= sample->value_size) {
        new_size = sample->value_size + alloc_slots;
        reallocated_values = realloc(sample->values, new_size * sizeof(int64_t));

        if (reallocated_values == NULL) {
            return -1;
        }

        sample->values = reallocated_values;
        sample->value_size = new_size;
    }

    sample->values[sample->value_count] = value;
    sample->value_count++;

    return 0;
}

int cprof_sample_add_attribute(struct cprof_sample *sample, uint64_t attribute)
{
    size_t new_size;
    size_t alloc_slots = 32;
    uint64_t *reallocated_attributes;

    if (sample->attributes == NULL) {
        sample->attributes = calloc(alloc_slots, sizeof(uint64_t));

        if (sample->attributes == NULL) {
            return -1;
        }

        sample->attributes_count = 0;
        sample->attributes_size = alloc_slots;
    }

    if (sample->attributes_count >= sample->attributes_size) {
        new_size = sample->attributes_size + alloc_slots;
        reallocated_attributes = realloc(sample->attributes, new_size * sizeof(uint64_t));

        if (reallocated_attributes == NULL) {
            return -1;
        }

        sample->attributes = reallocated_attributes;
        sample->attributes_size = new_size;
    }

    sample->attributes[sample->attributes_count] = attribute;
    sample->attributes_count++;

    return 0;
}

int cprof_sample_add_timestamp(struct cprof_sample *sample, uint64_t timestamp)
{
    size_t new_size;
    size_t alloc_slots = 32;
    uint64_t *reallocated_timestamps;

    if (sample->timestamps_unix_nano == NULL) {
        sample->timestamps_unix_nano = calloc(alloc_slots, sizeof(uint64_t));

        if (sample->timestamps_unix_nano == NULL) {
            return -1;
        }

        sample->timestamps_count = 0;
        sample->timestamps_size = alloc_slots;
    }

    if (sample->timestamps_count >= sample->timestamps_size) {
        new_size = sample->timestamps_size + alloc_slots;
        reallocated_timestamps = realloc(sample->timestamps_unix_nano, new_size * sizeof(uint64_t));

        if (reallocated_timestamps == NULL) {
            return -1;
        }

        sample->timestamps_unix_nano = reallocated_timestamps;
        sample->timestamps_size = new_size;
    }

    sample->timestamps_unix_nano[sample->timestamps_count] = timestamp;
    sample->timestamps_count++;

    return 0;
}

void cprof_sample_destroy(struct cprof_sample *sample)
{
    if (sample != NULL) {
        if (sample->location_index) {
            free(sample->location_index);
        }

        if (sample->values != NULL) {
            free(sample->values);
        }

        if (sample->attributes != NULL) {
            free(sample->attributes);
        }

        if (sample->timestamps_unix_nano != NULL) {
            free(sample->timestamps_unix_nano);
        }

        free(sample);
        return;
    }
}


void cprof_sample_destroy_all(struct cprof_profile *profile)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cprof_sample *sample;

    cfl_list_foreach_safe(head, tmp, &profile->samples) {
        sample = cfl_list_entry(head, struct cprof_sample, _head);
        cprof_sample_destroy(sample);
    }
}

struct cprof_value_type *cprof_sample_type_create(struct cprof_profile *profile,
                                                  int64_t type, int64_t unit, int aggregation_temporality)
{
    struct cprof_value_type *sample_type;

    sample_type = calloc(1, sizeof(struct cprof_value_type));
    if (!sample_type) {
        return NULL;
    }

    sample_type->type = type;
    sample_type->unit = unit;
    sample_type->aggregation_temporality = aggregation_temporality;

    cfl_list_add(&sample_type->_head, &profile->sample_type);
    return sample_type;
}

struct cprof_value_type *cprof_sample_type_str_create(struct cprof_profile *profile, char *type_str, char *unit_str,
                                                      int aggregation_temporality)
{
    int64_t type;
    int64_t unit;
    struct cprof_value_type *sample_type;

    if (!profile || !type_str || !unit_str) {
        return NULL;
    }

    type = cprof_profile_string_add(profile, type_str, -1);
    if (type <= 0) {
        return NULL;
    }

    unit = cprof_profile_string_add(profile, unit_str, -1);
    if (unit <= 0) {
        return NULL;
    }

    sample_type = cprof_sample_type_create(profile, type, unit, aggregation_temporality);
    if (!sample_type) {
        return NULL;
    }

    return sample_type;
}

void cprof_sample_type_destroy(struct cprof_value_type *sample_type)
{
    if (sample_type != NULL) {
        free(sample_type);
    }
}

void cprof_sample_type_destroy_all(struct cprof_profile *profile)
{
    struct cfl_list *head;
    struct cfl_list *tmp;
    struct cprof_value_type *sample_type;

    cfl_list_foreach_safe(head, tmp, &profile->sample_type) {
        sample_type = cfl_list_entry(head, struct cprof_value_type, _head);
        cprof_sample_type_destroy(sample_type);
    }
}
