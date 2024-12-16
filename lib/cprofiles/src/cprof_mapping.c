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

struct cprof_mapping *cprof_mapping_create(struct cprof_profile *profile)
{
    struct cprof_mapping *instance;

    instance = calloc(1, sizeof(struct cprof_mapping));

    if (instance == NULL) {
        return NULL;
    }

    cfl_list_add(&instance->_head, &profile->mappings);

    return instance;
}

void cprof_mapping_destroy(struct cprof_mapping *instance)
{
    if (instance != NULL) {
        if (instance->attributes != NULL) {
            free(instance->attributes);

            instance->attributes = NULL;
        }

        free(instance);
    }
}


int cprof_mapping_add_attribute(struct cprof_mapping *mapping, uint64_t attribute)
{
    size_t new_size;
    size_t alloc_slots = 32;
    uint64_t *reallocated_attributes;

    if (mapping->attributes == NULL) {
        mapping->attributes = calloc(alloc_slots, sizeof(uint64_t));

        if (mapping->attributes == NULL) {
            return -1;
        }

        mapping->attributes_count = 0;
        mapping->attributes_size = alloc_slots;
    }

    if (mapping->attributes_count >= mapping->attributes_size) {
        new_size = mapping->attributes_size + alloc_slots;
        reallocated_attributes = realloc(mapping->attributes, new_size * sizeof(uint64_t));

        if (reallocated_attributes == NULL) {
            return -1;
        }

        mapping->attributes = reallocated_attributes;
        mapping->attributes_size = new_size;
    }

    mapping->attributes[mapping->attributes_count] = attribute;
    mapping->attributes_count++;

    return 0;
}