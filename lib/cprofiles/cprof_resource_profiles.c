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

struct cprof_resource_profiles *cprof_resource_profiles_create(char *schema_url) {
    struct cprof_resource_profiles *instance;
    cfl_sds_t                       schema_url_copy;

    instance = calloc(1, sizeof(struct cprof_resource_profiles));

    if (instance != NULL) {
        if (schema_url == NULL) {
            free(instance);

            instance = NULL;
        }
        else {
            schema_url_copy = cfl_sds_create(schema_url);

            if (schema_url_copy == NULL) {
                free(instance);

                instance = NULL;
            }
            else {
                instance->schema_url = schema_url_copy;
                cfl_list_init(&instance->scope_profiles);
            }
        }
    }

    return instance;
}


void cprof_resource_profiles_destroy(struct cprof_resource_profiles *instance) {
    struct cfl_list             *iterator;
    struct cprof_scope_profiles *scope_profiles;
    struct cfl_list             *iterator_backup;

    if (instance != NULL) {
        if (instance->schema_url != NULL) {
            cfl_sds_destroy(instance->schema_url);
        }

        if (instance->resource != NULL) {
            cprof_resource_destroy(instance->resource);
        }

        cfl_list_foreach_safe(iterator,
                              iterator_backup,
                              &instance->scope_profiles) {
            scope_profiles = cfl_list_entry(iterator,
                                            struct cprof_scope_profiles, _head);

            cfl_list_del(&scope_profiles->_head);

            cprof_scope_profiles_destroy(scope_profiles);
        }

        free(instance);
    }
}
