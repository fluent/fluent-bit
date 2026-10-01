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

#include <time.h>
#include "cprof_tests.h"

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>


void print_profile(struct cprof_profile *profile)
{
    int i;
    int sample_index = 0;
    uint64_t location_idx;
    char *tmp;
    struct cfl_list *head;
    struct cfl_list *type_head;
    struct cprof_sample *sample;
    struct cprof_value_type *sample_type;

    printf("\n");
    printf("--- profile debug\n");
    printf("Profile Duration: %" PRId64 " nanoseconds\n\n", profile->duration_nanos);
    printf("Samples:\n");

    cfl_list_foreach(head, &profile->samples) {
        sample = cfl_list_entry(head, struct cprof_sample, _head);

        printf("  Sample #%d:\n", ++sample_index);

        printf("    Locations:\n");
        for (i = 0; i < sample->location_index_count; ++i) {
            location_idx = sample->location_index[i];
            tmp = profile->string_table[location_idx];
            if (tmp[0] == '\0') {
                printf("      [Empty String: No Function Name]\n");
            } else {
                printf("      Function: %s\n", tmp);
            }
        }

        printf("    Values:\n");
        size_t value_index = 0;
        cfl_list_foreach(type_head, &profile->sample_type) {
            sample_type = cfl_list_entry(type_head, struct cprof_value_type, _head);
            if (value_index < sample->value_count) {
                printf("      %s: %" PRId64 " %s\n",
                       profile->string_table[sample_type->type],
                       sample->values[value_index],
                       profile->string_table[sample_type->unit]);
            }
            value_index++;
        }

        if (sample->timestamps_count > 0) {
            printf("    Timestamps:\n");
            for (i = 0; i < sample->timestamps_count; ++i) {
                printf("      Timestamp %d: %" PRIu64 " ns\n", i, sample->timestamps_unix_nano[i]);
            }
        } else {
            printf("    [No Timestamps]\n");
        }

        printf("\n");  // Add space between samples for readability
    }
    printf("String Table:\n");
    for (i = 0; i < profile->string_table_count; i++) {
        printf("  %d: '%s'\n", i, profile->string_table[i]);
    }
    printf("\n");
}

/* a basic test */
static void test_profile()
{
    int i;
    int ret;
    size_t id;
    int64_t cpu_time;
    int64_t memory_usage;
    uint64_t timestamp;
    char *functions[3] = {"main", "foo", "bar"};
    uint64_t function_locations[3];
    struct cprof *cprof;
    struct cprof_profile *profile;
    struct cprof_sample *sample;

    /* create context */
    cprof = cprof_create();
    TEST_CHECK(cprof != NULL);

    /* create profile */
    profile = cprof_profile_create();
    TEST_CHECK(profile != NULL);

    cprof_sample_type_str_create(profile, "CPU time", "ns", CPROF_AGGREGATION_TEMPORALITY_CUMULATIVE);
    cprof_sample_type_str_create(profile, "Memory usage", "bytes", CPROF_AGGREGATION_TEMPORALITY_DELTA);

    /* register the string functions */
    for (i = 0; i < 3; i++) {
        id = cprof_profile_string_add(profile, functions[i], -1);
        TEST_CHECK(id != 0);
        function_locations[i] = id;
    }

    srand(time(NULL));

    for (i = 0; i < 3; i++) {
        /* create sample */
        sample = cprof_sample_create(profile);
        TEST_CHECK(sample != NULL);


        ret = cprof_sample_add_location_index(sample, function_locations[i]);
        TEST_CHECK(ret == 0);

        /* random CPU and Memory */
        cpu_time = (rand() % 1000) + 1;
        memory_usage = (rand() % 1024) + 128;

        /* current time in nanoseconds */
        timestamp = (uint64_t) time(NULL) * 1e9;

        /* add CPU time */
        ret = cprof_sample_add_value(sample, cpu_time);
        TEST_CHECK(ret == 0);

        /* add memory usage */
        ret = cprof_sample_add_value(sample, memory_usage);
        TEST_CHECK(ret == 0);

        /* add timestamp */
        ret = cprof_sample_add_timestamp(sample, timestamp);
        TEST_CHECK(ret == 0);
    }

    print_profile(profile);

    cprof_profile_destroy(profile);

    /* destroy context */
    cprof_destroy(cprof);
}

static void test_linked_object_destruction()
{
    struct cprof *context;
    struct cprof_resource_profiles *resource_profiles;
    struct cprof_scope_profiles *scope_profiles;
    struct cprof_profile *profile;
    struct cprof_location *location;

    cprof_profile_destroy(NULL);
    cprof_resource_destroy(NULL);

    context = cprof_create();
    TEST_ASSERT(context != NULL);

    resource_profiles = cprof_resource_profiles_create("");
    TEST_ASSERT(resource_profiles != NULL);
    TEST_CHECK(cprof_resource_profiles_add(context, resource_profiles) == 0);
    TEST_CHECK(cfl_list_size(&context->profiles) == 1);

    scope_profiles = cprof_scope_profiles_create(resource_profiles, "");
    TEST_ASSERT(scope_profiles != NULL);
    TEST_CHECK(cfl_list_size(&resource_profiles->scope_profiles) == 1);

    profile = cprof_profile_create();
    TEST_ASSERT(profile != NULL);
    cfl_list_add(&profile->_head, &scope_profiles->profiles);
    TEST_CHECK(cfl_list_size(&scope_profiles->profiles) == 1);

    TEST_ASSERT(cprof_sample_create(profile) != NULL);
    cprof_sample_destroy_all(profile);
    TEST_CHECK(cfl_list_size(&profile->samples) == 0);

    TEST_ASSERT(cprof_sample_type_create(profile, 0, 0, 0) != NULL);
    cprof_sample_type_destroy_all(profile);
    TEST_CHECK(cfl_list_size(&profile->sample_type) == 0);

    TEST_ASSERT(cprof_mapping_create(profile) != NULL);
    cprof_mapping_destroy(cfl_list_entry(profile->mappings.next,
                                         struct cprof_mapping,
                                         _head));
    TEST_CHECK(cfl_list_size(&profile->mappings) == 0);

    location = cprof_location_create(profile);
    TEST_ASSERT(location != NULL);
    TEST_ASSERT(cprof_line_create(location) != NULL);
    cprof_line_destroy(cfl_list_entry(location->lines.next,
                                     struct cprof_line,
                                     _head));
    TEST_CHECK(cfl_list_size(&location->lines) == 0);
    cprof_location_destroy(location);
    TEST_CHECK(cfl_list_size(&profile->locations) == 0);

    TEST_ASSERT(cprof_function_create(profile) != NULL);
    cprof_function_destroy(cfl_list_entry(profile->functions.next,
                                          struct cprof_function,
                                          _head));
    TEST_CHECK(cfl_list_size(&profile->functions) == 0);

    TEST_ASSERT(cprof_attribute_unit_create(profile) != NULL);
    cprof_attribute_unit_destroy(cfl_list_entry(profile->attribute_units.next,
                                                struct cprof_attribute_unit,
                                                _head));
    TEST_CHECK(cfl_list_size(&profile->attribute_units) == 0);

    TEST_ASSERT(cprof_link_create(profile) != NULL);
    cprof_link_destroy(cfl_list_entry(profile->link_table.next,
                                      struct cprof_link,
                                      _head));
    TEST_CHECK(cfl_list_size(&profile->link_table) == 0);

    cprof_profile_destroy(profile);
    TEST_CHECK(cfl_list_size(&scope_profiles->profiles) == 0);

    cprof_scope_profiles_destroy(scope_profiles);
    TEST_CHECK(cfl_list_size(&resource_profiles->scope_profiles) == 0);

    cprof_resource_profiles_destroy(resource_profiles);
    TEST_CHECK(cfl_list_size(&context->profiles) == 0);

    cprof_destroy(context);
}

TEST_LIST = {
    {"profile", test_profile},
    {"linked_object_destruction", test_linked_object_destruction},
    { 0 }
};
