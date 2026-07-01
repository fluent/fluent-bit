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

/* Scope profiles */
struct cprof_scope_profiles *cprof_scope_profiles_create(
                                struct cprof_resource_profiles *resource_profiles,
                                char *schema_url) {
    struct cprof_scope_profiles *instance;
    cfl_sds_t                    schema_url_copy;

    instance = calloc(1, sizeof(struct cprof_scope_profiles));

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
                cfl_list_init(&instance->profiles);
                cfl_list_add(&instance->_head, &resource_profiles->scope_profiles);
            }
        }
    }

    return instance;
}


void cprof_scope_profiles_destroy(struct cprof_scope_profiles *instance) {
    struct cprof_profile *profile;
    struct cfl_list      *iterator;
    struct cfl_list      *iterator_backup;

    if (instance != NULL) {
        if (instance->schema_url != NULL) {
            cfl_sds_destroy(instance->schema_url);
        }

        if (instance->scope != NULL) {
            cprof_instrumentation_scope_destroy(instance->scope);
        }

        cfl_list_foreach_safe(iterator,
                              iterator_backup,
                              &instance->profiles) {
            profile = cfl_list_entry(iterator,
                                     struct cprof_profile, _head);

            cfl_list_del(&profile->_head);

            cprof_profile_destroy(profile);
        }

        free(instance);
    }
}
