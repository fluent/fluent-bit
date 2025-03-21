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

struct cprof_location *cprof_location_create(struct cprof_profile *profile)
{
    struct cprof_location *instance;

    instance = calloc(1, sizeof(struct cprof_location));

    if (instance == NULL) {
        return NULL;
    }

    cfl_list_init(&instance->lines);

    cfl_list_add(&instance->_head, &profile->locations);

    return instance;
}

int cprof_location_add_attribute(struct cprof_location *location, uint64_t attribute)
{
    size_t new_size;
    size_t alloc_slots = 32;
    uint64_t *reallocated_attributes;

    if (location->attributes == NULL) {
        location->attributes = calloc(alloc_slots, sizeof(uint64_t));

        if (location->attributes == NULL) {
            return -1;
        }

        location->attributes_count = 0;
        location->attributes_size = alloc_slots;
    }

    if (location->attributes_count >= location->attributes_size) {
        new_size = location->attributes_size + alloc_slots;
        reallocated_attributes = realloc(location->attributes, new_size * sizeof(uint64_t));

        if (reallocated_attributes == NULL) {
            return -1;
        }

        location->attributes = reallocated_attributes;
        location->attributes_size = new_size;
    }

    location->attributes[location->attributes_count] = attribute;
    location->attributes_count++;

    return 0;
}

void cprof_location_destroy(struct cprof_location *instance)
{
    struct cprof_line *line;
    struct cfl_list   *iterator;
    struct cfl_list   *iterator_backup;

    if (instance != NULL) {
        if (instance->attributes != NULL) {
            free(instance->attributes);

            instance->attributes = NULL;
        }

        cfl_list_foreach_safe(iterator,
                              iterator_backup,
                              &instance->lines) {
            line = cfl_list_entry(iterator,
                                  struct cprof_line, _head);

            cfl_list_del(&line->_head);

            cprof_line_destroy(line);
        }

        free(instance);
    }
}
